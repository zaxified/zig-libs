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
    /// §12.1.4: "A PreSharedKey proposal is invalid if ... the
    /// PreSharedKeyID has psktype set to resumption and usage set to
    /// reinit" (likewise `branch`) outside the one operation that admits
    /// it — §11.2's reinitialization, §11.3's subgroup branching. Both
    /// sections restate it as a flat MUST ("A PreSharedKey proposal with
    /// type resumption and usage reinit MUST be considered invalid"), and
    /// neither operation is built here, so in this module the rule is
    /// unconditional. See `joinByExternalCommit` for the one place where
    /// §12.4.3.2 appears to advise otherwise.
    ResumptionPskUsageNotAllowed,
    /// §12.1.4: "A PreSharedKey proposal is invalid if ... the psk_nonce is
    /// not of length KDF.Nh."
    PskNonceLength,
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
    /// The Commit being processed removes THIS client. Not a rejection of
    /// the message — the Commit is valid and the removal has taken effect
    /// for everyone else; it is the only outcome §12.4.2 leaves a removed
    /// member, which is why it is an error rather than a silent success.
    ///
    /// §12.4.2's closing note: "Note that clients need to be prepared to
    /// receive a valid Commit message that removes them from the group. In
    /// this case, the client cannot send any more messages in the group and
    /// SHOULD promptly delete its group state and secret tree. (A client
    /// might keep the secret tree for a short time to decrypt late messages
    /// in the previous epoch.)" That is the whole of what it asks, and it
    /// is NOT "advance an epoch": §12.3 blanks this client's leaf before the
    /// path is decrypted, so no `UpdatePath` ciphertext is addressed to it,
    /// no `commit_secret` can be derived, and §12.4.2's `confirmation_tag`
    /// bullet has nothing to check against. A removed member therefore
    /// cannot reach the new epoch at all — no implementation can.
    ///
    /// The group object is left AT THE PREVIOUS EPOCH and unpoisoned, which
    /// is exactly the state the note's parenthesis describes: still able to
    /// decrypt late messages from the epoch that just ended, and — because
    /// the caller now knows — obliged to stop sending and to drop the state
    /// promptly. `Group` cannot enforce either of those; the deletion is the
    /// caller's, and this error is how it is told to perform it.
    RemovedFromGroup,

    // ── §12.2's SECOND procedure: an external Commit's proposal list.
    // Five errors rather than one `InvalidProposalList`, because unlike a
    // regular Commit's blacklist this is a four-line whitelist and each
    // line fails for a materially different reason — and because a caller
    // that gets one of these back should be able to tell "you sent the
    // wrong kind of proposal" from "you sent two of the right kind".
    /// §12.2: an external Commit's list carried a proposal type the
    /// whitelist does not name (anything but ExternalInit, Remove, PSK).
    ProposalNotAllowedInExternalCommit,
    /// §12.2: "Exactly one ExternalInit" — there was none.
    MissingExternalInit,
    /// §12.2: "Exactly one ExternalInit" — there were several.
    MultipleExternalInit,
    /// §12.2: "At most one Remove proposal, with which the joiner removes
    /// an old version of themselves" — there were several.
    MultipleRemoveInExternalCommit,
    /// §12.4.3.2: "The Commit MUST NOT include any proposals by reference,
    /// since an external joiner cannot determine the validity of proposals
    /// sent within the group."
    ProposalByReferenceInExternalCommit,
    /// §6.2: a `PublicMessage` from a `new_member_commit` sender carried a
    /// `membership_tag`. That sender is not a member and holds no
    /// `membership_key`, so §6.2's `select` gives it no tag field at all.
    UnexpectedMembershipTag,
    /// §12.4.3.2: "External Commits MUST contain a path field."
    ExternalCommitRequiresPath,
    /// The `GroupInfo` offered for an external join carries no
    /// `external_pub` extension, so §8.3's sender half has no key to
    /// encapsulate to (§12.4.3.2: "to join a group via an external Commit,
    /// a new member needs a GroupInfo with an external_pub extension").
    ExternalPubUnavailable,
} || tree.Error || keyschedule.Error || transcript.Error || std.mem.Allocator.Error ||
    std.crypto.errors.Error || error{ Malformed, EndOfStream };

/// One application-provided external PSK: RFC 9420 §8.4's `psk_id` and the
/// key material it names. `Group` resolves `PreSharedKeyID.external` against
/// a list of these.
pub const ExternalPsk = struct {
    psk_id: []const u8,
    psk: []const u8,
};

/// One prior-epoch `resumption_psk` the CALLER hands in, for the one
/// situation where the library cannot look one up for itself: a client
/// entering a group by §12.4.3.2 external Commit has no epoch history to
/// look in, because it has not lived through any epoch of that group yet.
///
/// **What the library checks.** Only that a `PreSharedKeyID` in the Commit
/// names exactly this entry — same `usage`, same `psk_group_id`, same
/// `psk_epoch` (§8.4 identifies a resumption PSK by group and epoch; the
/// `usage` is required to match too, see below) — and that `secret` is
/// `KDF.Nh` wide, which a `resumption_psk` is by construction.
///
/// **What the library CANNOT check, and what is therefore the caller's
/// half of the trust.** That `secret` really is the `resumption_psk` the
/// named group derived at the named epoch. A group entered by external
/// Commit has no way to recompute it, no signature over it, and no member
/// to ask. If the caller hands in a value an attacker chose, this module
/// will mix it into the key schedule exactly as instructed — and the
/// failure is not silent, but it is late and it is somebody else's: every
/// real member resolves the same `PreSharedKeyID` from its OWN remembered
/// history, derives a different `psk_secret`, and rejects the Commit at
/// §12.4.2's `confirmation_tag` bullet. So a wrong secret costs a failed
/// join, not a compromised group — but only because the members are
/// checking, which is the reason this type is not a way to inject key
/// material into a group that would otherwise refuse it.
///
/// The caller's obligation, stated as one sentence: hand in a value this
/// client itself derived while it was a member of the named group at the
/// named epoch, from storage it trusts as much as its own signature key.
pub const ResumptionPsk = struct {
    /// §8.4's `ResumptionPSKUsage`. Part of the match because here the
    /// entry is an AUTHORIZATION rather than a lookup: a caller that hands
    /// in a secret "for usage X" has not thereby authorized usage Y, whose
    /// `PSKLabel` — and therefore whose contribution to `psk_secret` — is a
    /// different value. (A group's own `resumption_history` is keyed by
    /// group and epoch only, and deliberately: there the secret is one this
    /// group derived, and §8.4 makes the same `resumption_psk` serve every
    /// usage. The asymmetry is between "what the secret IS" and "what the
    /// caller said it may be used for".)
    usage: keyschedule.ResumptionPskUsage,
    /// The group the epoch belongs to — NOT necessarily the group being
    /// joined. §11.2/§11.3 point resumption PSKs at a predecessor group;
    /// a resync points them at the group being rejoined.
    group_id: []const u8,
    epoch: u64,
    /// Exactly `KDF.Nh` bytes.
    secret: []const u8,
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
            // Root of the epoch key schedule: every group key derives from
            // this. `random`'s fallback on `EntropyUnavailable` is silent and
            // low-entropy, so this secret needs the fail-closed call instead.
            try params.io.randomSecure(&init_secret);
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
            // No resumption source at all: this client has lived through no
            // epoch of a group it is only now joining, and the `GroupInfo`
            // that would name the group has not been decrypted yet. A
            // resumption `PreSharedKeyID` in the `GroupSecrets` is therefore
            // `error.PskNotAvailable` here — §11.2/§11.3's reinit and branch
            // flows are the ones that would need it, and neither is built.
            const psks = try resolvePsksFromIds(gpa, group_secrets.psks, params.external_psks, .{});
            defer gpa.free(psks);
            const psk_secret = try keyschedule.pskSecret(S, gpa, psks);

            var joiner: [S.Nh]u8 = undefined;
            @memcpy(&joiner, group_secrets.joiner_secret);
            const welcome_secret = try keyschedule.welcomeSecret(S, joiner, psk_secret);

            const gi_bytes = try welcome_mod.decryptGroupInfo(S, arena, welcome_secret, w.encrypted_group_info);
            var gi_reader = codec.Reader.init(gi_bytes);
            const group_info = try welcome_mod.GroupInfo.decode(arena, &gi_reader);
            if (!gi_reader.atEnd()) return error.Malformed;
            try checkGroupInfoVersionAndSuite(S, group_info.group_context);

            // ── §12.4.3.3's tree + §12.4.3.1's integrity block.
            var rt = try verifiedTreeFromGroupInfo(gpa, arena, group_info, params.ratchet_tree);

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

        /// §12.4.3.3's "the tree, from the extension or from out of band"
        /// followed by §12.4.3.1's tree-integrity block and §12.4.3's
        /// `GroupInfo` signature check — the three things that have to
        /// happen, in this order, before ANY field of a received
        /// `GroupInfo` may be believed.
        ///
        /// Shared by the two ways of entering a group from one
        /// (`fromWelcome` and `joinByExternalCommit`) because the order is
        /// the whole point: the signature cannot be checked before the tree
        /// is known (the signer is a leaf index), and the tree cannot be
        /// trusted before its root hash is matched against the
        /// `GroupContext` the signature covers. Two copies would be two
        /// chances to reorder it.
        ///
        /// The tree is allocated from `arena` and aliases either
        /// `out_of_band` or the `GroupInfo`'s own buffer, so both must
        /// outlive it — this file's standing convention.
        fn verifiedTreeFromGroupInfo(
            gpa: std.mem.Allocator,
            arena: std.mem.Allocator,
            group_info: welcome_mod.GroupInfo,
            out_of_band: ?[]const u8,
        ) !tree.RatchetTree {
            var rt: tree.RatchetTree = blk: {
                if (out_of_band) |ext_bytes| {
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
            try welcome_mod.verifyTreeHash(S, gpa, &rt, group_info.group_context);
            try treekem.validateParentHashes(S, gpa, &rt);
            try verifyEveryLeafSignature(S, gpa, &rt, group_info.group_context.group_id);
            const signer_key = try leafSignatureKey(&rt, group_info.signer);
            try group_info.verifySignature(S, gpa, signer_key);
            return rt;
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

        /// RFC 9420 §12.4.2, bullet by bullet, for BOTH kinds of Commit —
        /// a regular one from a `member` sender and §12.4.3.2's external
        /// one from a `new_member_commit` sender. On success the group has
        /// advanced one epoch; on failure see this file's note on
        /// atomicity.
        ///
        /// **Where the external branch diverges, and why each divergence is
        /// forced.** §12.4.2 states one procedure with two "if this is an
        /// external Commit" clauses in it, but three earlier steps also
        /// have to change, and they change because the sender is not in the
        /// tree yet:
        ///
        ///   * no `membership_tag` (§6.2 gives a `new_member_commit`
        ///     `PublicMessage` no tag field at all — the sender holds no
        ///     `membership_key`), so the signature is the ONLY thing
        ///     authenticating the message. That is not a weakening: an
        ///     external Commit is meant to be acceptable from a stranger,
        ///     and what binds it to this group is the `GroupContext` inside
        ///     §6.1's `FramedContentTBS` plus the `confirmation_tag`, which
        ///     nobody without the group's `external_priv` can produce;
        ///   * the signature key comes out of `commit.path.leaf_node`
        ///     (§6.1's `new_member_commit` bullet), because there is no
        ///     leaf to read it from. The joiner therefore picks its own
        ///     verification key — again not a weakening, because §12.4.3.2
        ///     leaves accepting the identity in that leaf to the
        ///     application ("Whether existing members of the group will
        ///     accept or reject an external Commit follows the same rules
        ///     that are applied to other handshake messages");
        ///   * §12.2's list validation is a different procedure — a
        ///     whitelist, see `validateExternalProposalList`;
        ///   * the sender's leaf index is COMPUTED, not transmitted (the
        ///     `Sender` arm carries no index), so both sides derive it from
        ///     the post-proposal tree and a disagreement shows up as a
        ///     failed `confirmation_tag`;
        ///   * §12.3's last-but-one bullet substitutes §8.3's `init_secret`
        ///     for the previous epoch's.
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

            // The body is read BEFORE the signature check rather than after,
            // because an external Commit's verification key is inside it
            // (§6.1's `new_member_commit` bullet). Reading a union arm
            // authenticates nothing on its own; every byte of it is still
            // covered by the signature verified two statements below.
            const commit = switch (pm.content.body) {
                .commit => |c| c,
                else => return error.WrongContentType,
            };

            const external = pm.content.sender == .new_member_commit;

            // Bullets 2-3: unprotect with the CURRENT epoch's keys, then
            // check the signature — both against the OLD GroupContext.
            //
            // `member_committer` is the sender's leaf index for a regular
            // Commit. An external Commit has none yet: §12.4.2's
            // path bullet ASSIGNS one, after the proposals have been
            // applied, so it cannot be known here.
            var member_committer: u32 = undefined;
            const ac = pm.authenticatedContent();
            if (external) {
                try rejectExternalCommitFraming(pm);
                // §12.4.3.2: "External Commits MUST contain a path field
                // (and is therefore a 'full' Commit)." Checked here rather
                // than at bullet 7's `needs_path` because the LeafNode in
                // it is what the next line verifies the signature with — a
                // pathless external Commit has nothing to check at all.
                const path = commit.path orelse return error.ExternalCommitRequiresPath;
                const key = try leafNodeSignatureKey(path.leaf_node);
                try framing.verifyFramedContent(S, gpa, key, ac, old_gc);
            } else {
                member_committer = switch (pm.content.sender) {
                    .member => |i| i,
                    else => return error.UnexpectedSenderType,
                };
                const committer_key = try leafSignatureKey(&self.ratchet_tree, member_committer);
                try framing.verifyMembershipTag(S, gpa, self.secrets.membership_key, pm, old_gc);
                try framing.verifyFramedContent(S, gpa, committer_key, ac, old_gc);
            }

            // Bullet 4: resolve every ProposalOrRef, then §12.2-validate the
            // resulting list — by one of that section's TWO procedures.
            // Resolution needs the proposal messages, which may themselves
            // contribute LeafNodes (an Add's KeyPackage), so they are copied
            // into the arena too.
            const resolved = try self.resolveProposals(arena, gpa, commit.proposals, params.proposal_msgs, old_gc);
            defer gpa.free(resolved);
            if (external) {
                try self.validateExternalProposalList(resolved);
            } else {
                try self.validateProposalList(gpa, resolved, member_committer);
            }

            // §12.4.2's closing note, which is the ONLY thing that section
            // asks of a member the Commit removes — see
            // `Error.RemovedFromGroup` for the quotation and for why
            // "process it like anyone else" is not among the options.
            // Answered HERE, at the last point where all three of these
            // hold:
            //
            //   * the Commit has been authenticated as far as a removed
            //     member ever can authenticate it (signature + membership
            //     tag + §12.2's list validation). It cannot go further: the
            //     `confirmation_tag` bullet needs the new epoch's
            //     `confirmation_key`, and deriving that needs the
            //     `commit_secret` this client can no longer obtain;
            //   * the tree is still the one this client belongs to, so the
            //     answer does not depend on whether §7.7's truncation is
            //     about to drop this client's own leaf out of the array;
            //   * the poison flag is not yet set, so the previous epoch's
            //     state survives for the "short time to decrypt late
            //     messages" the same note allows.
            //
            // Deliberately AFTER §12.2's validation: a removed member is
            // still a conformant peer and must not report a malformed
            // proposal list as its own removal.
            for (resolved) |rp| switch (rp.proposal) {
                .remove => |idx| if (idx == self.my_leaf_index) return error.RemovedFromGroup,
                else => {},
            };

            // From here on the tree is mutated; any failure poisons.
            self.poisoned = true;

            // Bullets 5-6 (§12.3): apply the proposals, in §12.3's order,
            // and resolve the PSKs they name. No caller-supplied resumption
            // secrets on this path even for an external Commit: a RECEIVER
            // is a member and has its own history, and letting the receiving
            // application hand in resumption secrets would let it agree with
            // a sender's forged PSK instead of catching it.
            var applied = try self.applyProposals(arena, gpa, resolved, params.external_psks, &.{});
            defer applied.deinit(gpa);
            const new_extensions = applied.extensions;
            const psk_secret = applied.psk_secret;

            // Bullet 7: path presence.
            if (applied.needs_path and commit.path == null) return error.PathRequired;

            // Bullet 8's FIRST clause: "If this is an external Commit,
            // assign the sender the leftmost blank leaf node in the new
            // ratchet tree." AFTER §12.3's application, so a Remove in this
            // same Commit (§12.2's resync flavor) can free the very leaf the
            // sender lands in — and BEFORE anything reads the committer's
            // index. See `tree.RatchetTree.assignBlankLeaf`.
            const committer: u32 = if (external)
                @intCast(try self.ratchet_tree.assignBlankLeaf())
            else
                member_committer;

            // Bullet 8: validate and apply the path.
            var commit_secret = keyschedule.zeroSecret(S);
            var derived: []const treekem.PathSecretEntry = &.{};
            if (commit.path) |path| {
                // §7.3 via §12.4.2: source MUST be `commit`.
                if (path.leaf_node.leaf_node_source != .commit) return error.InvalidUpdatePath;
                try verifyLeafSignature(S, gpa, path.leaf_node, .commit, self.group_id, committer);

                // The committer's encryption key must actually change —
                // read BEFORE the merge replaces the leaf. An external
                // committer has no current leaf to compare against (the
                // slot just assigned is blank by construction), so §12.4.2's
                // "different from the committer's current leaf node" has no
                // subject and is vacuous rather than skipped.
                if (!external) {
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

                // The receiver is still in the tree: a Commit that removes
                // it returned `RemovedFromGroup` above, before any of this
                // ran. That is what makes the failures below real failures
                // — nothing that reaches this call is expected to be
                // undecryptable.
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

            // Bullets 10-11: the key schedule. §12.3's last-but-one bullet
            // ("If there is an ExternalInit proposal, use it to derive the
            // init_secret for use later in Commit processing") REPLACES the
            // salt of §8's first Extract; it does not mix with the previous
            // epoch's value. That is what lets a stranger — who by
            // definition does not have `init_secret_[n-1]` — land in the
            // same epoch as everyone else.
            const init_secret = if (applied.external_init) |kem|
                try self.externalInitSecret(kem)
            else
                self.secrets.init_secret;

            const secrets = try keyschedule.deriveEpoch(
                S,
                gpa,
                init_secret,
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

        /// RFC 9420 §8.3's RECEIVING half, wired to this epoch: recover the
        /// `init_secret` a joiner encapsulated to the group's published
        /// `external_pub`. `external_priv` is `KEM.DeriveKeyPair(
        /// external_secret)` for the epoch the Commit was made against —
        /// i.e. the CURRENT one, which is why this is a method and not a
        /// free function.
        fn externalInitSecret(self: *const Self, kem_output: []const u8) ![S.Nh]u8 {
            if (kem_output.len != S.Kem.Npk) return error.WrongKeyLength;
            const kp = keyschedule.externalKeyPair(S, self.secrets.external_secret);
            return keyschedule.externalInitReceiver(S, kem_output[0..S.Kem.Npk].*, kp);
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
            return self.commitInner(allocator, params, .member);
        }

        /// Which of §12.4's two Commit flavors `commitInner` is building.
        ///
        /// One function builds both, rather than an `externalCommit` beside
        /// `createCommit`, for the same reason `applyProposals` is shared
        /// between sending and receiving: §12.4.1's step list is stated once
        /// and the external flavor is stated as a handful of substitutions
        /// inside it (§12.4.3.2: "In principle, external Commits work like
        /// regular Commits. However, their content has to meet a specific
        /// set of requirements"). A second copy would be a second place for
        /// the provisional-GroupContext ordering, the sign-then-confirm
        /// ordering and §12.3's application order to drift — and a drift in
        /// any of them produces a Commit that looks fine and that nobody
        /// can process.
        const CommitMode = union(enum) {
            /// §12.4.1: an existing member commits from its own leaf.
            member,
            /// §12.4.3.2: a newcomer commits itself into the group. It
            /// carries the two things that are normally read off the
            /// group — because a non-member has neither.
            external: struct {
                /// §8.3's `init_secret`, the joiner's own half of the
                /// exchange whose `kem_output` is in the ExternalInit
                /// proposal. It REPLACES the previous epoch's `init_secret`,
                /// which a non-member does not have.
                init_secret: [S.Nh]u8,
                /// The identity half of the leaf the joiner will occupy —
                /// its signature key, credential, capabilities and
                /// extensions. Its encryption key is NOT used: §7.5 samples
                /// a fresh one for every commit-sourced leaf.
                leaf: tree.LeafNode,
                /// Prior-epoch `resumption_psk` values the caller supplied.
                /// It lives on THIS arm and not in `CreateCommitParams`
                /// because a member committing into its own group has a
                /// `resumption_history` and needs no such thing — the type
                /// says where the hole is.
                resumption_psks: []const ResumptionPsk = &.{},
            },
        };

        fn commitInner(
            self: *Self,
            allocator: std.mem.Allocator,
            params: CreateCommitParams,
            mode: CommitMode,
        ) !Created {
            try self.check();
            const arena = self.arena.allocator();
            const gpa = self.gpa;
            const external = mode == .external;

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
            // §12.2 opens with "A group member creating a Commit and a group
            // member processing a Commit MUST verify..." — so a sender runs
            // the same procedure, and the same CHOICE of procedure, that
            // every receiver will.
            if (external) {
                try self.validateExternalProposalList(resolved);
            } else {
                try self.validateProposalList(gpa, resolved, self.my_leaf_index);
            }
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
            var applied = try self.applyProposals(arena, gpa, resolved, params.external_psks, switch (mode) {
                .external => |e| e.resumption_psks,
                .member => &.{},
            });
            defer applied.deinit(gpa);

            // ── §12.4.1 bullet 4's FIRST sub-bullet: "If this is an external
            // Commit, assign the sender the leftmost blank leaf node in the
            // new ratchet tree." The mirror of `processCommit`'s, run at the
            // same point of the same sequence — after §12.3's application,
            // before the path — because that is the only way two parties
            // that never exchange the index arrive at the same one.
            if (external) self.my_leaf_index = @intCast(try self.ratchet_tree.assignBlankLeaf());

            // ── §12.4.1 bullets 4-5: the path.
            //
            // The committer's leaf content is duplicated into the arena
            // FIRST: `stageUpdatePath` blanks the sender's slot before it
            // builds the replacement, which frees the list containers the
            // old leaf owned — reading them afterwards would be a
            // use-after-free the DebugAllocator catches only if a test
            // happens to look at them. An external committer has no old leaf
            // to lose; its content comes from the KeyPackage it published.
            const base_leaf = switch (mode) {
                .member => try dupLeafNode(arena, try self.ownLeaf()),
                .external => |e| e.leaf,
            };

            var commit: content.Commit = .{ .proposals = por, .path = null };
            var commit_secret = keyschedule.zeroSecret(S);
            var staged: ?treekem.Staged(S) = null;
            var new_leaf_priv = self.my_encryption_priv;

            // §12.4.3.2: "External Commits MUST contain a path field (and is
            // therefore a 'full' Commit)." `applied.needs_path` is already
            // true for any list holding an ExternalInit (§12.4's
            // `pathRequiredTypes`), so this disjunct is redundant today —
            // and it is spelled out because the two rules are independent
            // and only one of them is unconditional.
            const want_path = external or applied.needs_path or !params.omit_path_when_allowed;
            if (want_path) {
                var path_secret_0: [S.Nh]u8 = undefined;
                // Commit secret for the UpdatePath: forward secrecy of the
                // ratchet tree rides on it, so — as with `init_secret` above —
                // fail closed rather than accept `random`'s silent fallback.
                try params.io.randomSecure(&path_secret_0);
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
            //
            // §12.4.3.2: "The sender type for the AuthenticatedContent
            // encapsulating the external Commit MUST be
            // new_member_commit." That arm carries NO index (§6's `Sender`
            // gives it an empty struct), which is precisely why both sides
            // have to compute the leaf independently. §6.1 still puts the
            // GroupContext in the TBS for it, so an external Commit is
            // bound to this group and this epoch exactly as a member's is.
            const fc: framing.FramedContent = .{
                .group_id = self.group_id,
                .epoch = self.epoch,
                .sender = if (external) .new_member_commit else .{ .member = self.my_leaf_index },
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

            // §12.3's ExternalInit bullet, from the SENDER's side: the
            // joiner already holds §8.3's `init_secret` (it drew it when it
            // encapsulated to `external_pub`), so unlike the receiver it
            // does not recover it from the proposal — it IS the party that
            // chose it. Same value, opposite half of the exchange; the
            // `confirmation_tag` below is what proves the two agree.
            const init_secret = switch (mode) {
                .member => self.secrets.init_secret,
                .external => |e| e.init_secret,
            };
            const secrets = try keyschedule.deriveEpoch(
                S,
                gpa,
                init_secret,
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
            // An external committer holds no `membership_key` — it is not a
            // member of the epoch it is committing against — and §6.2 gives
            // its `PublicMessage` no field to put a tag in. `null` here is
            // not "we skipped a step": it is the wire format.
            const mtag: ?[S.Nm]u8 = if (external)
                null
            else
                try framing.membershipTag(S, gpa, self.secrets.membership_key, fc, ac.auth, old_gc);
            const commit_msg: framing.MLSMessage = .{
                .public_message = .{
                    .content = fc,
                    .auth = ac.auth,
                    .membership_tag = if (mtag) |*t| t else null,
                },
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

        // ── §12.4.3.2: joining by external Commit ─────────────────────────

        /// Everything `joinByExternalCommit` needs. Byte slices are borrowed
        /// for the duration of the call; whatever the group retains is
        /// copied into its own arena.
        pub const ExternalJoinParams = struct {
            /// Draws §8.3's HPKE ephemeral, §7.4's `path_secret[0]`, the
            /// fresh leaf key pair and the ciphertext ephemerals.
            io: std.Io,
            /// The published `MLSMessage(GroupInfo)` — §12.4.1's third
            /// output, unencrypted, as a Delivery Service caches it. MUST
            /// carry an `external_pub` extension (§12.4.3.2), and each one
            /// is good for exactly ONE external join, because that join
            /// changes the epoch.
            group_info_msg: []const u8,
            /// This client's own whole `MLSMessage(KeyPackage)`. ONLY its
            /// `leaf_node`'s identity half is used — signature key,
            /// credential, capabilities, extensions — because §7.5 samples a
            /// fresh `encryption_key` for the commit-sourced leaf this
            /// builds, and no `init_key` is ever encapsulated to (there is
            /// no `Welcome`). It is taken as a whole KeyPackage anyway, for
            /// symmetry with `create`/`fromWelcome` and because a client
            /// that can join a group has one.
            key_package_msg: []const u8,
            signature_key_pair: S.Sig.KeyPair,
            /// Proposals to commit ALONGSIDE the ExternalInit, which this
            /// function contributes itself (the caller cannot: its
            /// `kem_output` is drawn here). §12.2's whitelist admits only a
            /// Remove — the "resync" flavor, removing an old appearance of
            /// this same client — and PreSharedKeys. Anything else is
            /// `error.ProposalNotAllowedInExternalCommit`, and so is a
            /// second ExternalInit.
            proposals: []const content.Proposal = &.{},
            /// §12.4.3.3's out-of-band tree, when the `GroupInfo` carries no
            /// `ratchet_tree` extension.
            ratchet_tree: ?[]const u8 = null,
            external_psks: []const ExternalPsk = &.{},
            /// Prior-epoch `resumption_psk` values this client obtained OUT
            /// OF BAND — from its own storage, from before it lost state, or
            /// from a predecessor group. Nothing else can supply them: a
            /// group entered this way has no epoch history, which is why a
            /// resumption `PreSharedKeyID` in `proposals` is
            /// `error.PskNotAvailable` without this list.
            ///
            /// Each entry's `secret` MUST be `KDF.Nh` bytes, checked for the
            /// whole list up front. Read `ResumptionPsk` before using this:
            /// the library can check that a `PreSharedKeyID` names an entry,
            /// and cannot check that the entry is genuine.
            resumption_psks: []const ResumptionPsk = &.{},
            authenticated_data: []const u8 = &.{},
            include_ratchet_tree: bool = true,
            include_external_pub: bool = false,
            group_info_extensions: []const tree.Extension = &.{},
            policy: Policy = .{},
        };

        /// What an external join produces: the joiner's own group state, and
        /// the messages §12.4.1's steps produce for everyone else.
        pub const ExternalJoin = struct {
            /// The joiner, in the NEW epoch — already advanced, exactly as
            /// `createCommit` leaves a committer.
            group: Self,
            /// `commit` and `group_info` as `createCommit` produces them.
            /// `welcome` is always `null`: §12.2's whitelist admits no Add,
            /// so an external Commit adds nobody but its own sender, and
            /// that sender needs no Welcome — it has the group state
            /// already.
            messages: Created,
        };

        /// RFC 9420 §12.4.3.2: turn a published `GroupInfo` into an external
        /// Commit and the group state that Commit lands the sender in — the
        /// second of the two ways into a group, and the one that needs
        /// nobody already inside to be online.
        ///
        /// **What the joiner can and cannot check, stated plainly.** It
        /// verifies the tree against the signed `tree_hash`, the tree's
        /// parent-hash chain, and the `GroupInfo` signature under the
        /// signer's leaf key — the same three checks `fromWelcome` runs, via
        /// the same function. It CANNOT verify the `confirmation_tag` the
        /// `GroupInfo` carries: doing so needs that epoch's
        /// `confirmation_key`, which is exactly what a non-member does not
        /// have. A forged tag is nonetheless not silently absorbed, it is
        /// only detected LATER and by somebody else: the tag feeds §8.2's
        /// `interim_transcript_hash`, so a wrong one gives the joiner a
        /// different `confirmed_transcript_hash` for the new epoch than
        /// every member computes, and the Commit is rejected by all of them
        /// at §12.4.2's `confirmation_tag` bullet. The joiner ends up in an
        /// epoch of one; it never ends up in the group holding a state
        /// nobody else holds.
        ///
        /// **The identity in the leaf is not vouched for by anything here**,
        /// and by design: §12.4.3.2 says accepting an external Commit
        /// "follows the same rules that are applied to other handshake
        /// messages", i.e. it is the receiving application's call. This
        /// function signs the joiner's own leaf with the joiner's own key
        /// and stops there.
        ///
        /// **Resumption PSKs come in through `resumption_psks`, and the
        /// trust in them is the caller's.** A group entered this way starts
        /// with an empty `resumption_history`, so there is nothing to look a
        /// resumption `PreSharedKeyID` up in; `ExternalJoinParams
        /// .resumption_psks` is how the caller hands in prior-epoch secrets
        /// it obtained out of band — the resync case, where this client was
        /// in this group before and kept the secret. What is checked here:
        /// that every entry is `KDF.Nh` wide, and that a `PreSharedKeyID`
        /// resolves only against an entry naming the same `usage`,
        /// `psk_group_id` and `psk_epoch`. What is NOT and cannot be
        /// checked: that the value is really that group's `resumption_psk`
        /// for that epoch. A wrong one is caught by the members, not here —
        /// they resolve the same id from their own history and reject the
        /// Commit at the `confirmation_tag`. See `ResumptionPsk`.
        ///
        /// **§12.4.3.2's own suggestion for gating the resync flavor cannot
        /// be followed literally.** Its closing paragraph offers, as
        /// application advice, allowing a resync Commit "only if [it]
        /// contain[s] a 'reinit' PSK proposal that demonstrates the joining
        /// member's presence in a prior epoch of the group". But §12.1.4
        /// makes a PreSharedKey proposal invalid when it names usage
        /// `reinit` outside §11.2's reinitialization, and §11.2 restates
        /// that as a flat MUST — and an external Commit is not a
        /// reinitialization. A conforming receiver must therefore reject
        /// exactly the proposal that advice describes, and this module does
        /// (`error.ResumptionPskUsageNotAllowed`, see `validatePskProposal`).
        /// The gate is still available with usage `application`, which
        /// demonstrates presence in a prior epoch identically: only the
        /// client that held that epoch's `resumption_psk` can produce a
        /// Commit the members accept.
        pub fn joinByExternalCommit(
            gpa: std.mem.Allocator,
            allocator: std.mem.Allocator,
            params: ExternalJoinParams,
        ) !ExternalJoin {
            const arena_ptr = try gpa.create(std.heap.ArenaAllocator);
            errdefer gpa.destroy(arena_ptr);
            arena_ptr.* = .init(gpa);
            errdefer arena_ptr.deinit();
            const arena = arena_ptr.allocator();

            // §8.4: a resumption PSK IS the named epoch's `resumption_psk`,
            // which is `KDF.Nh` wide by construction. Checked over the WHOLE
            // list here rather than at the point of use, so that a
            // mis-sized entry is reported even when this Commit happens not
            // to name it — a caller whose storage layer is handing back the
            // wrong thing should learn it on the first join, not the tenth.
            for (params.resumption_psks) |p| {
                if (p.secret.len != S.Nh) return error.WrongSecretLength;
            }

            // ── our own KeyPackage, for the identity half of the leaf we
            // are about to occupy. Verified like `create` verifies the
            // founder's: a group whose newest leaf does not self-verify is
            // one every receiver rejects, and finding that out here is
            // cheaper than finding it out from silence.
            const kp_copy = try arena.dupe(u8, params.key_package_msg);
            var kp_reader = codec.Reader.init(kp_copy);
            const kp_msg = try framing.MLSMessage.decode(arena, &kp_reader);
            if (!kp_reader.atEnd()) return error.Malformed;
            if (kp_msg != .key_package) return error.Malformed;
            const my_kp = kp_msg.key_package;
            if (my_kp.cipher_suite != S.id) return error.CipherSuiteMismatch;
            try my_kp.verifySignature(S, gpa);
            try verifyLeafSignature(S, gpa, my_kp.leaf_node, .key_package, null, null);

            // ── the GroupInfo. Its GroupContext extensions and (usually)
            // its tree are retained, so decode from an arena-owned copy.
            const gi_copy = try arena.dupe(u8, params.group_info_msg);
            var gi_reader = codec.Reader.init(gi_copy);
            const gi_msg = try framing.MLSMessage.decode(arena, &gi_reader);
            if (!gi_reader.atEnd()) return error.Malformed;
            if (gi_msg != .group_info) return error.WrongContentType;
            const group_info = gi_msg.group_info;
            try checkGroupInfoVersionAndSuite(S, group_info.group_context);

            const rt = try verifiedTreeFromGroupInfo(gpa, arena, group_info, params.ratchet_tree);

            // ── §8.3's sender half. `external_pub` is the ONLY thing in the
            // GroupInfo that a non-member could not have computed for
            // itself, and it is what makes the whole mechanism work: the
            // joiner encapsulates a fresh `init_secret` to it, and only a
            // holder of `external_secret` for this epoch — i.e. an actual
            // member — can recover it.
            const ext_pub_bytes = (try group_info.externalPub()) orelse return error.ExternalPubUnavailable;
            if (ext_pub_bytes.len != S.Kem.Npk) return error.WrongKeyLength;
            const ext_init = try keyschedule.externalInitSender(S, ext_pub_bytes[0..S.Kem.Npk].*, params.io);

            // ── the proposal list: §12.2's mandatory ExternalInit first,
            // then whatever the caller added. FIRST rather than last only
            // because a reader of the wire bytes should see the proposal
            // that makes this Commit external before anything else; §12.2's
            // whitelist is explicitly order-independent ("not necessarily in
            // this order"), and §12.3's application order is fixed and
            // unrelated.
            const sources = try gpa.alloc(CommitSource, params.proposals.len + 1);
            defer gpa.free(sources);
            sources[0] = .{ .by_value = .{ .external_init = &ext_init.kem_output } };
            for (params.proposals, sources[1..]) |p, *slot| slot.* = .{ .by_value = p };

            // ── the bootstrap state the Commit is built against: the group
            // AS THE GroupInfo DESCRIBES IT, one epoch back.
            const conf = group_info.group_context.confirmed_transcript_hash;
            if (group_info.group_context.tree_hash.len != S.Hash.digest_length) return error.Malformed;
            // §8.2 allows exactly two widths — a digest, or epoch 0's
            // zero-length string. Same rule, same reason as `fromWelcome`.
            if (conf.len != S.Hash.digest_length and conf.len != 0) return error.Malformed;

            var self: Self = .{
                .gpa = gpa,
                .arena = arena_ptr,
                .policy = params.policy,
                .group_id = group_info.group_context.group_id,
                .epoch = group_info.group_context.epoch,
                .tree_hash = undefined,
                .confirmed_transcript_hash = undefined,
                .confirmed_len = conf.len,
                .extensions = group_info.group_context.extensions,
                .interim_transcript_hash = try transcript.interimTranscriptHash(
                    S,
                    conf,
                    group_info.confirmation_tag,
                ),
                .ratchet_tree = rt,
                // Every secret of the epoch being committed AGAINST, which
                // a non-member has none of. Zeroed rather than left
                // `undefined` so that a mis-wired external branch produces a
                // deterministic, testable wrong answer instead of whatever
                // was on the stack — and `commitInner` reads exactly two
                // fields of it, `init_secret` and `membership_key`, both of
                // which the `.external` mode replaces or suppresses. The
                // whole struct is overwritten with the NEW epoch's secrets
                // before this function returns.
                .secrets = std.mem.zeroes(keyschedule.EpochSecrets(S)),
                // Assigned by `commitInner`'s §12.4.1 bullet-4 step, after
                // the proposals have been applied. Nothing reads it before
                // then; `ownLeaf` — the one thing that would — is not on the
                // `.external` path.
                .my_leaf_index = undefined,
                .my_encryption_priv = @splat(0),
                .my_path_secrets = .empty,
                .resumption_history = .empty,
                .pending_updates = .empty,
            };
            @memcpy(&self.tree_hash, group_info.group_context.tree_hash);
            @memcpy(self.confirmed_transcript_hash[0..conf.len], conf);
            // The §7.3 rule this object owns, applied to the leaf we are
            // about to occupy — the same check an Add's KeyPackage gets in
            // `applyProposals`. `stageUpdatePath` carries the capabilities
            // and extensions over unchanged, so answering it for the
            // KeyPackage's leaf answers it for the commit-sourced leaf that
            // will be built from it.
            try self.checkLeafSelfConsistent(my_kp.leaf_node);

            // The re-encoded GroupContext must equal the bytes the
            // GroupInfo's signature covered. If it does not, the context
            // this Commit is signed under is not the one the members hold,
            // and every one of them rejects it — a mismatch worth catching
            // here, where it can still be attributed.
            {
                const gc_bytes = try group_info.groupContextBytes(gpa);
                defer if (gc_bytes.owned) gpa.free(gc_bytes.bytes);
                const re = try self.groupContextAlloc(gpa);
                defer gpa.free(re);
                if (!std.mem.eql(u8, gc_bytes.bytes, re)) return error.Malformed;
            }

            const messages = try self.commitInner(allocator, .{
                .io = params.io,
                .signature_key_pair = params.signature_key_pair,
                .proposals = sources,
                .external_psks = params.external_psks,
                .authenticated_data = params.authenticated_data,
                .include_ratchet_tree = params.include_ratchet_tree,
                .include_external_pub = params.include_external_pub,
                .group_info_extensions = params.group_info_extensions,
            }, .{ .external = .{
                .init_secret = ext_init.init_secret,
                .leaf = my_kp.leaf_node,
                .resumption_psks = params.resumption_psks,
            } });

            return .{ .group = self, .messages = messages };
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
            /// §12.3: "If there is an ExternalInit proposal, use it to
            /// derive the init_secret for use later in Commit processing" —
            /// the proposal's `kem_output`, or `null` for a regular Commit
            /// (whose §12.2 procedure rejects the proposal outright). A
            /// view into the arena-owned proposal.
            external_init: ?[]const u8,
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
            /// Non-empty only on the §12.4.3.2 external-join path — see
            /// `ResumptionPsk`. A member processing or creating a regular
            /// Commit resolves resumption PSKs from its own history and
            /// nothing else.
            resumption_psks: []const ResumptionPsk,
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
                    // §12.1.3's validity condition, re-checked HERE and not
                    // only in the §12.2 pass, so this function's own
                    // contract ("a leaf index named by a Remove names a
                    // non-blank leaf") holds for every caller. It is judged
                    // against the tree as it stands at this point of §12.3's
                    // order, which is the SAME occupancy the §12.2 pass saw:
                    // the only step that ran before it is the Update loop,
                    // and an Update replaces an occupied leaf with another
                    // occupied leaf. A Remove earlier in this same list
                    // cannot have blanked this leaf either — §12.2 rejects
                    // "multiple Update and/or Remove proposals that apply to
                    // the same leaf", and an external Commit's list carries
                    // at most one Remove — so the sequential reading and the
                    // "judge the whole list against the pre-Commit tree"
                    // reading coincide, and the sequential one additionally
                    // catches a same-leaf duplicate that ever slipped past
                    // §12.2.
                    try self.validateRemoveProposal(idx);
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
            const psks = try self.resolvePsks(gpa, psk_ids, external_psks, resumption_psks);
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

            // §12.3's "If there is an ExternalInit proposal, use it to
            // derive the init_secret". Only NOTED here, not consumed: the
            // derivation belongs at the key-schedule step, and the two
            // sides of an external Commit reach the same value by opposite
            // halves of §8.3 (`externalInitSender`/`externalInitReceiver`),
            // so this function — which is shared by both — must not pick
            // one. `validateExternalProposalList` has already established
            // there is at most one.
            var external_init: ?[]const u8 = null;
            for (resolved) |rp| {
                if (rp.proposal == .external_init) external_init = rp.proposal.external_init;
            }

            return .{
                .extensions = new_extensions,
                .added = added_slice,
                .added_leaves = added_leaves,
                .psk_ids = psk_ids,
                .psk_secret = psk_secret,
                .external_init = external_init,
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
                    // §12.2's first bullet: "it contains an individual
                    // proposal that is invalid as specified in Section
                    // 12.1". §12.1.3's condition is the one below. Run here,
                    // BEFORE the poison flag is set, so a Commit refused for
                    // it does not also destroy the group — the same reason
                    // the Add KeyPackage checks were hoisted out of
                    // `applyProposals` into `commitInner`'s pre-mutation
                    // phase. It stays enforced in `applyProposals` as well;
                    // see the note there.
                    //
                    // AFTER the committer check, deliberately: a self-Remove
                    // names an occupied leaf, so the two never compete, and
                    // keeping §12.2's own rule first preserves the error a
                    // caller already sees for it.
                    try self.validateRemoveProposal(idx);
                    try appendUnique(gpa, &touched, idx);
                    try removed.append(gpa, idx);
                },
                .psk => |id| {
                    // §12.1.4's own three conditions, before §12.2's.
                    try validatePskProposal(id);
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

        /// RFC 9420 §12.2's SECOND procedure, for an EXTERNAL Commit, plus
        /// the one list rule §12.4.3.2 states instead of §12.2.
        ///
        /// **This is a whitelist, and that is the whole difference.** The
        /// regular procedure above enumerates ways a list can be bad and
        /// accepts everything else; this one enumerates what a list may
        /// contain and rejects everything else — "the list is valid if it
        /// contains only the following proposals ... Exactly one
        /// ExternalInit ... At most one Remove ... Zero or more
        /// PreSharedKey ... No other proposals". Reusing the blacklist here
        /// and bolting an ExternalInit counter onto it would silently admit
        /// Adds, Updates, GroupContextExtensions and ReInits from a party
        /// that is not yet a member, which is exactly what the split
        /// procedure exists to prevent. It takes no committer index because
        /// there is no committer leaf yet.
        ///
        /// It DOES consult the tree, for one thing and in a second pass:
        /// §12.1's per-proposal validity, which §12.2 folds into both
        /// procedures and which for a Remove (§12.1.3) is a question about
        /// the tree. The second pass is not cosmetic — the four list-shape
        /// rules above are about the LIST and must keep reporting first, so
        /// that a list with two Removes is still refused as
        /// `MultipleRemoveInExternalCommit` rather than as whichever of the
        /// two happens to name a blank leaf.
        ///
        /// **Two rules deliberately NOT carried over from the regular
        /// procedure**, both because §12.2's external list is closed and
        /// neither appears in it:
        ///
        ///   * "multiple PreSharedKey proposals that reference the same
        ///     PreSharedKeyID". §8.4's chain is position-dependent and
        ///     would happily process a repeat; both sides derive the same
        ///     `psk_secret` from the same repeated list, so it costs
        ///     correctness nothing. A stricter implementer could
        ///     legitimately read §12.2's "invalid as specified in
        ///     Section 12.1" spirit as applying and reject it — noted in
        ///     `SPEC.md`;
        ///   * §12.2's closing "after processing the Commit the ratchet
        ///     tree is invalid" rule, which is NOT skipped — it is
        ///     `checkKeyUniqueness`, run once per epoch transition for both
        ///     kinds of Commit.
        ///
        /// §12.2's own extra condition on the Remove ("the LeafNode in the
        /// path field MUST meet the same criteria as would the LeafNode in
        /// an Update for the removed leaf ... the credential MUST present a
        /// set of identifiers that is acceptable to the application for the
        /// removed participant") is an Authentication Service question, and
        /// so stays the application's for the same reason §7.3's credential
        /// bullet does — see this file's §7.3 boundary note.
        fn validateExternalProposalList(self: *const Self, list: []const Resolved) !void {
            var n_external_init: usize = 0;
            var n_remove: usize = 0;
            for (list) |rp| {
                // §12.4.3.2: "The Commit MUST NOT include any proposals by
                // reference, since an external joiner cannot determine the
                // validity of proposals sent within the group." Checked
                // per-entry rather than over `commit.proposals` so it reads
                // off the same list every other rule here does.
                if (rp.by_reference) return error.ProposalByReferenceInExternalCommit;
                switch (rp.proposal) {
                    .external_init => n_external_init += 1,
                    .remove => n_remove += 1,
                    // §12.2's whitelist says only "Zero or more PreSharedKey
                    // proposals"; §12.1.4's per-proposal conditions are
                    // stated about the proposal itself and so apply to both
                    // procedures.
                    .psk => |id| try validatePskProposal(id),
                    else => return error.ProposalNotAllowedInExternalCommit,
                }
            }
            if (n_external_init == 0) return error.MissingExternalInit;
            if (n_external_init > 1) return error.MultipleExternalInit;
            if (n_remove > 1) return error.MultipleRemoveInExternalCommit;

            // §12.1's per-proposal validity, after the list-shape rules. For
            // §12.4.3.2's resync flavor the Remove names the joiner's OWN
            // earlier leaf, so a stale one is the likeliest mistake there of
            // all the places a Remove appears.
            for (list) |rp| switch (rp.proposal) {
                .remove => |idx| try self.validateRemoveProposal(idx),
                else => {},
            };
        }

        /// RFC 9420 §12.1.4's three conditions that make a `PreSharedKey`
        /// PROPOSAL invalid, applied by both §12.2 procedures because
        /// §12.1.4 states them about the proposal and not about the list.
        ///
        /// **The `reinit`/`branch` rule is unconditional here, and the RFC
        /// is not self-consistent about it.** §12.1.4 makes the two usages
        /// invalid only outside §11.2's reinitialization and §11.3's
        /// branching; §11.2 and §11.3 each restate it flat ("A PreSharedKey
        /// proposal with type resumption and usage reinit MUST be considered
        /// invalid"). Neither operation is built in this module, so the
        /// conditional and the flat reading coincide and this is the flat
        /// one. Against that, §12.4.3.2's closing paragraph advises
        /// applications that they may "allow such resync commits only if
        /// they contain a 'reinit' PSK proposal that demonstrates the
        /// joining member's presence in a prior epoch of the group" — which
        /// is precisely the proposal §12.1.4 forbids, since an external
        /// Commit is not a reinitialization. That advice is non-normative
        /// ("can choose to") and §12.1.4's rule is a MUST, so the MUST wins;
        /// the implementable form of the same gate is a resumption PSK with
        /// usage `application`, which demonstrates presence in a prior epoch
        /// exactly as well. Noted in `SPEC.md`.
        /// RFC 9420 §12.1.3's condition that makes a `Remove` PROPOSAL
        /// invalid: `removed` must name a member of the group as the tree
        /// currently stands. (Paraphrased, not quoted — §12.1.3 states it as
        /// a sentence about the removed member, not as a tree predicate.)
        ///
        /// **A blank leaf that is still IN BOUNDS is the case worth naming.**
        /// §7.7 only truncates trailing blanks, so removing leaf 1 of a
        /// three-member group leaves the tree exactly as wide as it was, with
        /// `nodes[2]` blank. A bounds test alone therefore accepts a second
        /// Remove of leaf 1, and `RatchetTree.removeLeaf` blanks an
        /// already-blank slot without complaint — the Commit applies as a
        /// no-op and nothing looks wrong locally. That is precisely why it is
        /// worth rejecting: every conformant peer refuses that Commit, so
        /// accepting it does not produce a weaker group, it produces two
        /// groups that disagree about which Commits exist.
        ///
        /// Stated by §12.1 about the PROPOSAL and not about the list, so —
        /// exactly like `validatePskProposal` — it applies under both of
        /// §12.2's procedures.
        fn validateRemoveProposal(self: *const Self, idx: u32) !void {
            // `@as(usize, idx)` before the doubling, not after: `idx` is the
            // wire's `uint32` and `idx * 2` in u32 wraps for `idx >= 2^31`,
            // which in a safety build is a panic reachable from a decoded
            // message rather than a rejection.
            const node_index = @as(usize, idx) * 2;
            if (node_index >= self.ratchet_tree.nodes.len) return error.UnknownMember;
            if (self.ratchet_tree.nodes[node_index] == null) return error.UnknownMember;
        }

        fn validatePskProposal(id: keyschedule.PreSharedKeyId) !void {
            // "The psk_nonce is not of length KDF.Nh." §8.4's reason: the
            // nonce is what stops a re-used PSK from producing a re-used
            // `psk_input`, and a short one is a caller that skipped it.
            if (id.psk_nonce.len != S.Nh) return error.PskNonceLength;
            switch (id.id) {
                .external => {},
                .resumption => |r| switch (r.usage) {
                    .reinit, .branch => return error.ResumptionPskUsageNotAllowed,
                    // `application`, and the open enum's unassigned values:
                    // §12.1.4 names exactly two usages and this follows it
                    // literally rather than inventing a rule for codepoints
                    // a future document may define.
                    else => {},
                },
            }
        }

        fn appendUnique(gpa: std.mem.Allocator, list: *std.ArrayList(u32), v: u32) !void {
            for (list.items) |x| if (x == v) return error.InvalidProposalList;
            try list.append(gpa, v);
        }

        // ── PSK resolution ────────────────────────────────────────────────

        /// Where a §8.4 RESUMPTION PSK may be found. Split out because the
        /// three call sites have three genuinely different answers, and
        /// because two of the three fields are security-relevant enough
        /// that passing them positionally invites getting them the wrong
        /// way round.
        const ResumptionSource = struct {
            /// The group `history` belongs to. Load-bearing: a
            /// `PreSharedKeyID` names a resumption PSK by `psk_group_id`
            /// AND `psk_epoch`, so matching on the epoch alone would
            /// resolve an id naming SOMEBODY ELSE'S group to this group's
            /// own secret for that epoch number — and because both the
            /// sender and every receiver would apply the same wrong rule to
            /// the same id, they would agree, the Commit would be accepted,
            /// and nothing would look wrong from inside.
            group_id: []const u8 = &.{},
            /// Epochs this group actually lived through.
            history: []const ResumptionEntry = &.{},
            /// Prior-epoch secrets the CALLER supplied — see `ResumptionPsk`
            /// for which half of the trust that is.
            supplied: []const ResumptionPsk = &.{},
        };

        fn resolvePsks(
            self: *const Self,
            gpa: std.mem.Allocator,
            ids: []const keyschedule.PreSharedKeyId,
            external: []const ExternalPsk,
            supplied: []const ResumptionPsk,
        ) ![]keyschedule.PreSharedKey(S) {
            return resolvePsksFromIds(gpa, ids, external, .{
                .group_id = self.group_id,
                .history = self.resumption_history.items,
                .supplied = supplied,
            });
        }

        /// §8.4/§12.4.2: turn the `PreSharedKeyID` list into the key
        /// material `pskSecret` chains, POSITIONALLY — `out[i]` is the
        /// resolution of `ids[i]` and of nothing else, because §8.4's
        /// `PSKLabel` binds each PSK to its index and a resolver that
        /// grouped or reordered would produce a `psk_secret` that is wrong
        /// in a way no round trip can see (both sides would reorder alike).
        fn resolvePsksFromIds(
            gpa: std.mem.Allocator,
            ids: []const keyschedule.PreSharedKeyId,
            external: []const ExternalPsk,
            resumption: ResumptionSource,
        ) ![]keyschedule.PreSharedKey(S) {
            const out = try gpa.alloc(keyschedule.PreSharedKey(S), ids.len);
            errdefer gpa.free(out);
            for (ids, out) |id, *slot| {
                // Borrowed, not copied: §8.4 puts no width constraint on a
                // PSK (it is `KDF.Extract` IKM), so there is no fixed-size
                // buffer to copy into. The slices point into the caller's
                // `external` list, into `history` or into `supplied`, all of
                // which outlive the `pskSecret` call these feed.
                const secret: []const u8 = switch (id.id) {
                    .external => |psk_id| for (external) |e| {
                        if (std.mem.eql(u8, e.psk_id, psk_id)) break e.psk;
                    } else return error.PskNotAvailable,
                    .resumption => |r| blk: {
                        // (a) an epoch this group lived through. Consulted
                        // FIRST so that a caller-supplied entry can never
                        // shadow a secret the group derived itself.
                        if (std.mem.eql(u8, r.psk_group_id, resumption.group_id)) {
                            for (resumption.history) |*h| {
                                if (h.epoch == r.psk_epoch) break :blk h.secret[0..];
                            }
                        }
                        // (b) what the caller handed in, matched on the
                        // WHOLE triple — see `ResumptionPsk.usage`.
                        for (resumption.supplied) |s| {
                            if (s.usage == r.usage and
                                s.epoch == r.psk_epoch and
                                std.mem.eql(u8, s.group_id, r.psk_group_id))
                            {
                                break :blk s.secret;
                            }
                        }
                        return error.PskNotAvailable;
                    },
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
/// RFC 9420 §6.1's `new_member_commit` bullet: "The signature key in the
/// LeafNode in the Commit's path". The one sender type whose verification
/// key is inside the message it authenticates rather than in the tree —
/// see `processCommit`'s note on why that is not the weakening it looks
/// like.
fn leafNodeSignatureKey(leaf: tree.LeafNode) !std.crypto.sign.Ed25519.PublicKey {
    if (leaf.signature_key.len != 32) return error.WrongKeyLength;
    return std.crypto.sign.Ed25519.PublicKey.fromBytes(leaf.signature_key[0..32].*);
}

/// RFC 9420 §6.2's `select (PublicMessage.content.sender.sender_type)`: a
/// `new_member_commit` message has no `membership_tag` field.
///
/// **This guard is unreachable through `PublicMessage.decode` today, and it
/// is here anyway.** That decoder reads a tag only when the sender is
/// `member`, so bytes appended after a `new_member_commit` message come
/// back as trailing input and `processCommit`'s `reader.atEnd()` rejects
/// them as `error.Malformed` — which a test pins. What this guard covers is
/// the OTHER direction: a `PublicMessage` value that reached
/// `processCommit` by some path other than that decoder (a future
/// `PrivateMessage` unprotect, a caller-built struct) and carries a tag
/// nobody can have computed, since the sender holds no `membership_key`.
/// Accepting it would mean ignoring an authenticator rather than requiring
/// its absence, and the difference is invisible in a passing round trip.
fn rejectExternalCommitFraming(pm: framing.PublicMessage) !void {
    if (pm.membership_tag != null) return error.UnexpectedMembershipTag;
}

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

/// RFC 9420 §12.4.3.1's first joiner bullet, BOTH halves: "Verify that the
/// group's protocol version and cipher suite are ones this client
/// supports". The cipher-suite half was always here; the version half was
/// not, so a `GroupInfo` whose `GroupContext` declared some future version
/// was joined and operated as MLS 1.0 — the decoder does not reject it
/// either (`ProtocolVersion` is non-exhaustive on purpose: which versions
/// are acceptable is a validation decision, and this is where it is made).
///
/// One function rather than two adjacent lines at each call site, because
/// the two checks are one RFC bullet and the version half went missing
/// exactly by being a line somebody had to remember to add next to the
/// suite check.
fn checkGroupInfoVersionAndSuite(comptime S: type, gc: keyschedule.GroupContext) !void {
    if (gc.version != .mls10) return error.UnsupportedProtocolVersion;
    if (gc.cipher_suite != S.id) return error.CipherSuiteMismatch;
}

/// RFC 9420 §12.4.3.1's third tree-integrity bullet: "Verify the signature
/// on all the LeafNodes in the tree" — the one a joiner has to run over a
/// ratchet tree it is HANDED, as opposed to one it built by processing
/// Adds/Updates/Commits one at a time (where `verifyLeafSignature` already
/// runs on every leaf as it arrives).
///
/// Without this, whoever builds the `Welcome` (or the `GroupInfo` behind an
/// external Commit) picks the roster: `verifyTreeHash` only proves the tree
/// hashes to the value the `GroupInfo` signature covers, and that signature
/// is made by the welcomer itself, so a hostile welcomer can seat leaves
/// carrying any `Credential` it likes next to a `signature_key` it holds.
/// The tree hash then matches, the parent hashes match, the `GroupInfo`
/// signature matches — and the joiner reports forged members to the
/// application. Every leaf's own `LeafNodeTBS` signature is the only thing
/// that binds a `Credential` to a key the claimed member actually has.
///
/// The scheme and the signed content are the leaf's own, not the group's:
/// `VerifyWithLabel(leaf.signature_key, "LeafNodeTBS", LeafNodeTBS,
/// leaf.signature)` under the ciphersuite's `S.Sig` (`tree.LeafNode
/// .verifySignature`). `LeafNodeTBS` binds `group_id`/`leaf_index` only for
/// `update`- and `commit`-sourced leaves (§7.2), so the tree's own leaf
/// index is passed for every leaf and `key_package`-sourced leaves ignore
/// it — which is why a leaf cannot be moved between positions or between
/// groups once it is in one.
///
/// `leaf_node_source` is checked against the three §7.2 values rather than
/// against one expected value (all three legitimately occur in a tree: an
/// Add leaves `key_package`, an Update leaves `update`, a Commit's own leaf
/// leaves `commit`). A reserved/unknown source is rejected outright,
/// because `tbsEncode`'s `else` arm would sign it with no group binding at
/// all — i.e. an unknown source would be an `update` leaf that forgot to
/// bind its group.
fn verifyEveryLeafSignature(
    comptime S: type,
    gpa: std.mem.Allocator,
    t: *const tree.RatchetTree,
    group_id: []const u8,
) !void {
    const n_leaves = t.nLeaves();
    var i: u32 = 0;
    while (i < n_leaves) : (i += 1) {
        const node = t.nodes[@as(usize, i) * 2] orelse continue; // blank leaf
        const leaf = switch (node) {
            .leaf => |l| l,
            .parent => return error.Malformed, // a parent node at a leaf index
        };
        switch (leaf.leaf_node_source) {
            .key_package, .update, .commit => {},
            else => return error.Malformed,
        }
        try leaf.verifySignature(S, gpa, group_id, i);
    }
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

    // epoch 5: bob removes alice by value, and the SURVIVORS follow it.
    // What alice herself does with that Commit is §12.4.2's closing note
    // and is measured in its own test below — this one measures only that
    // removing a member does not disturb the members who remain.
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

test "§12.4.2's closing note: the member a Commit REMOVES learns exactly that, in both the truncating and the non-truncating shape" {
    // Two shapes, and the difference between them is the whole point of
    // running both.
    //
    //   * an INTERIOR leaf goes. §7.7 truncates only TRAILING blanks, so the
    //     tree stays as wide as it was and the removed member's own node
    //     index is still in bounds. What stopped it one step later was that
    //     no `UpdatePath` ciphertext is addressed to a leaf §12.3 had just
    //     blanked — `error.Malformed`;
    //   * the HIGHEST OCCUPIED leaf goes. §7.7 now drops the trailing blanks
    //     and the node array shrinks BELOW that member's own node index, so
    //     `treekem.processUpdatePath`'s bounds check speaks first —
    //     `error.InvalidLeafIndex`, a message about a leaf index the caller
    //     never supplied.
    //
    // Both answers are true and neither is usable, and both arrived with the
    // group poisoned although nothing had gone wrong with it. §12.4.2 asks
    // for one thing from a removed member and an epoch transition is not it;
    // see `Error.RemovedFromGroup` for the note's own words and for why no
    // implementation can do better than report the removal.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 91);
    const bob = try TestClient.init(aa, "bob", 92);
    const carol = try TestClient.init(aa, "carol", 93);
    const dave = try TestClient.init(aa, "dave", 94);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "closing-note",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    var b: Group(TestSuite) = undefined;
    var c_grp: Group(TestSuite) = undefined;
    var d_grp: Group(TestSuite) = undefined;
    {
        const c = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = alice.sig, .proposals = &.{
            .{ .by_value = .{ .add = bob.kp } },
            .{ .by_value = .{ .add = carol.kp } },
            .{ .by_value = .{ .add = dave.kp } },
        } });
        defer c.deinit(gpa);
        b = try bob.join(gpa, c.welcome.?, &.{});
        c_grp = try carol.join(gpa, c.welcome.?, &.{});
        d_grp = try dave.join(gpa, c.welcome.?, &.{});
    }
    defer b.deinit();
    defer c_grp.deinit();
    defer d_grp.deinit();
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    try testing.expectEqual(@as(u32, 2), c_grp.my_leaf_index);
    try testing.expectEqual(@as(u32, 3), d_grp.my_leaf_index);

    // ── Shape 1: carol's leaf 2 is INTERIOR, dave still holds leaf 3.
    {
        const carol_before = c_grp.epochAuthenticator();
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 2 } }},
        });
        defer c.deinit(gpa);

        // The Commit is valid — the survivors take it. Whatever carol does
        // with it is therefore about carol's ROLE, not about the message.
        try b.processCommit(.{ .commit_msg = c.commit });
        try d_grp.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &b);
        try expectSameEpoch(&a, &d_grp);
        try testing.expectEqual(@as(usize, 4), a.treeSize()); // no truncation

        try testing.expectError(error.RemovedFromGroup, c_grp.processCommit(.{ .commit_msg = c.commit }));
        // Not poisoned, not advanced, and byte-for-byte the state carol had
        // before she read the message: §12.4.2's note lets her keep it "for
        // a short time to decrypt late messages in the previous epoch", and
        // she cannot do that out of a group this library has declared dead.
        try testing.expect(!c_grp.poisoned);
        try testing.expectEqual(@as(u64, 1), c_grp.epoch);
        try testing.expectEqualSlices(u8, &carol_before, &c_grp.epochAuthenticator());
        try testing.expectEqual(@as(usize, 4), c_grp.treeSize());
    }

    // ── Shape 2: dave's leaf 3 is now the HIGHEST OCCUPIED leaf, and leaf 2
    // beside it is blank — so §7.7 drops the whole right half and the tree
    // shrinks past dave's own position.
    {
        const dave_before = d_grp.epochAuthenticator();
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 3 } }},
        });
        defer c.deinit(gpa);

        try b.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &b);
        // The truncation is REAL and it is what used to break this: four
        // leaves down to two, i.e. three nodes, against dave's own node
        // index `2 * 3`.
        try testing.expectEqual(@as(usize, 2), a.treeSize());

        try testing.expectError(error.RemovedFromGroup, d_grp.processCommit(.{ .commit_msg = c.commit }));
        try testing.expect(!d_grp.poisoned);
        try testing.expectEqual(@as(u64, 2), d_grp.epoch);
        try testing.expectEqualSlices(u8, &dave_before, &d_grp.epochAuthenticator());
        // Dave's OWN copy of the tree never shrank — the Commit was refused
        // before §12.3 was applied to it.
        try testing.expectEqual(@as(usize, 4), d_grp.treeSize());
    }
}

/// Re-frame a MEMBER's Commit around a different proposal list: re-sign with
/// the sender's own key and recompute the `membership_tag` from the group's
/// own `membership_key`. Strictly what a misbehaving MEMBER can do and nothing
/// an outsider can — which is the point, since a conformant sender will not
/// build the list this forges. `path`/`confirmation_tag` are left as they
/// were: every check it is used to drive runs at §12.4.2's bullet 4, before
/// either is read.
fn resignMemberCommit(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    commit_msg: []const u8,
    signer: TestSuite.Sig.KeyPair,
    membership_key: [TestSuite.Nh]u8,
    old_gc: []const u8,
    proposals: []const content.ProposalOrRef,
) ![]u8 {
    var r = codec.Reader.init(commit_msg);
    const msg = try framing.MLSMessage.decode(arena, &r);
    try testing.expect(r.atEnd());
    var pm = msg.public_message;
    var commit = pm.content.body.commit;
    commit.proposals = proposals;
    pm.content.body = .{ .commit = commit };

    const sig = try framing.signFramedContent(TestSuite, gpa, signer, .mls_public_message, pm.content, old_gc);
    const sig_bytes = sig.toBytes();
    pm.auth.signature = &sig_bytes;
    const tag = try framing.membershipTag(TestSuite, gpa, membership_key, pm.content, pm.auth, old_gc);
    pm.membership_tag = &tag;
    const out: framing.MLSMessage = .{ .public_message = pm };
    return out.encodeAlloc(gpa);
}

test "§12.1.3: a Remove naming a leaf that is BLANK but still in bounds is refused, and Removes of distinct leaves are not" {
    // The case a bounds test alone cannot see. §7.7 truncates only TRAILING
    // blanks, so vacating an interior leaf leaves the tree exactly as wide as
    // it was and `idx * 2 < nodes.len` still holds for the leaf nobody
    // occupies. `RatchetTree.removeLeaf` then blanks an already-blank slot
    // without complaining, so the second Remove applies as a silent no-op —
    // which is why it survived: nothing local looks wrong. What is wrong is
    // remote. Every conformant peer refuses that Commit under §12.1.3, so
    // accepting it does not weaken this group, it forks it.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 71);
    const bob = try TestClient.init(aa, "bob", 72);
    const carol = try TestClient.init(aa, "carol", 73);
    const dave = try TestClient.init(aa, "dave", 74);
    const erin = try TestClient.init(aa, "erin", 75);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "blank-remove",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    // epoch 1: alice fills leaves 1, 2 and 3. FOUR members, not three,
    // because leaf 3 is what keeps the tree from shrinking when leaf 1 goes —
    // in a three-member group the same Remove would leave a two-leaf tree and
    // the second Remove would be caught by the bounds test that already
    // existed, proving nothing.
    var c_grp: Group(TestSuite) = undefined;
    var d_grp: Group(TestSuite) = undefined;
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .add = bob.kp } },
                .{ .by_value = .{ .add = carol.kp } },
                .{ .by_value = .{ .add = dave.kp } },
            },
        });
        defer c.deinit(gpa);
        c_grp = try carol.join(gpa, c.welcome.?, &.{});
        d_grp = try dave.join(gpa, c.welcome.?, &.{});
    }
    defer c_grp.deinit();
    defer d_grp.deinit();
    try testing.expectEqual(@as(usize, 4), a.treeSize());

    // epoch 2: alice removes bob (leaf 1). The tree does NOT shrink.
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 1 } }},
        });
        defer c.deinit(gpa);
        try c_grp.processCommit(.{ .commit_msg = c.commit });
        try d_grp.processCommit(.{ .commit_msg = c.commit });
    }
    try testing.expectEqual(@as(u64, 2), a.epoch);
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    try expectSameEpoch(&a, &c_grp);
    try expectSameEpoch(&a, &d_grp);

    // ── THE REPRODUCTION: remove leaf 1 again. In bounds, blank, and until
    // §12.1.3 was enforced this returned a perfectly good Commit.
    try testing.expectError(error.UnknownMember, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 1 } }},
    }));
    // Refused at §12.2, BEFORE the tree was touched — so the sender's own
    // group survives its own mistake. (`applyProposals` enforces the same
    // condition, but reaching it would mean reaching it past the poison
    // flag.)
    try testing.expect(!a.poisoned);
    try testing.expectEqual(@as(u64, 2), a.epoch);

    // Past the end of the tree: the case the old bounds test did catch, kept
    // so that removing the bounds arm cannot pass unnoticed.
    try testing.expectError(error.UnknownMember, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 9 } }},
    }));
    // A leaf index whose DOUBLING overflows `u32`. The old test computed
    // `idx * 2` in the wire's own width, so this was an integer-overflow
    // panic in a safety build, reachable from a decoded message.
    try testing.expectError(error.UnknownMember, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 0x8000_0000 } }},
    }));

    // Unchanged, and checked here so the new condition cannot be what is
    // reporting them: §12.2's own two Remove rules still win where they
    // apply. The committer's leaf is occupied, so the self-Remove rule is not
    // shadowed by §12.1.3 …
    try testing.expectError(error.InvalidProposalList, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 0 } }},
    }));
    // … and the SAME leaf twice in one list is still §12.2's "multiple
    // Update and/or Remove proposals that apply to the same leaf", even
    // though both name an occupied leaf.
    try testing.expectError(error.InvalidProposalList, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{
            .{ .by_value = .{ .remove = 2 } },
            .{ .by_value = .{ .remove = 2 } },
        },
    }));
    try testing.expect(!a.poisoned);
    try testing.expectEqual(@as(u64, 2), a.epoch);

    // ── The RECEIVING half. A conformant sender will not build the list
    // above, so the only way a receiver ever sees one is a member that
    // re-frames its own Commit — which is exactly what a divergent or
    // malicious implementation is.
    {
        const old_gc = try c_grp.groupContextAlloc(gpa);
        defer gpa.free(old_gc);
        const membership_key = c_grp.secrets.membership_key;

        // epoch 3: an ordinary Commit from alice, to be spoiled. It refills
        // blank leaf 1 with erin (§12.1.1 places an Add in the leftmost
        // blank), which the legal-multi-Remove step below needs.
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = erin.kp } }},
        });
        defer c.deinit(gpa);

        const bad = try resignMemberCommit(gpa, aa, c.commit, alice.sig, membership_key, old_gc, &.{
            .{ .proposal = .{ .remove = 1 } },
        });
        defer gpa.free(bad);
        try testing.expectError(error.UnknownMember, c_grp.processCommit(.{ .commit_msg = bad }));
        // Refused at bullet 4, so carol is not poisoned and can still follow
        // the REAL Commit — which is what makes the refusal a rejection of
        // the message rather than a denial of service against the receiver.
        try testing.expect(!c_grp.poisoned);
        try testing.expectEqual(@as(u64, 2), c_grp.epoch);

        try c_grp.processCommit(.{ .commit_msg = c.commit });
        try d_grp.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &c_grp);
        try expectSameEpoch(&a, &d_grp);
        try testing.expectEqual(@as(u64, 3), a.epoch);
        try testing.expectEqual(@as(usize, 4), a.treeSize());
    }

    // ── And the legal shape stays legal: TWO Removes in one Commit naming
    // DISTINCT occupied leaves (erin at 1 and carol at 2). §12.2 forbids two
    // proposals against the SAME leaf, not two Removes; refusing this would
    // be the obvious over-correction. Dave, who survives at leaf 3, follows
    // it — so the two sides are shown to agree, not merely not to error.
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .remove = 1 } },
                .{ .by_value = .{ .remove = 2 } },
            },
        });
        defer c.deinit(gpa);
        try d_grp.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &d_grp);
    }
    try testing.expectEqual(@as(u64, 4), a.epoch);
    // Leaf 3 is still occupied, so §7.7 truncates nothing — which is the very
    // condition that made the blank interior leaf reachable in the first
    // place, re-asserted here rather than assumed.
    try testing.expectEqual(@as(usize, 4), a.treeSize());

    // …and §7.7's truncation still runs when the LAST leaf goes: removing
    // dave leaves alice alone and the tree collapses to one leaf. The
    // shrinking path is downstream of the new check and must be untouched.
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 3 } }},
        });
        defer c.deinit(gpa);
    }
    try testing.expectEqual(@as(u64, 5), a.epoch);
    try testing.expectEqual(@as(usize, 1), a.treeSize());
    // And a Remove of a leaf the truncation just dropped is refused by the
    // bounds arm, not by the blankness arm — both are live.
    try testing.expectError(error.UnknownMember, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 3 } }},
    }));
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

test "§12.4.2 bullet 1: a Commit from a STALE epoch (a replay of one already processed) is rejected before anything else runs" {
    // `processCommit`'s very first check is `content.epoch == self.epoch`.
    // Skipping it does not read as "accept a forged Commit" in the obvious
    // way, because the rest of `processCommit` still depends on state
    // (`old_gc`, `confirmed_transcript_hash`) that has already moved on —
    // but that dependency is exactly why this needs its own test rather
    // than trusting a later check to catch it: NOTHING else in this
    // function's ~500 lines is labelled "the epoch guard", so a defect
    // here is invisible to every other assertion in this file.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 24);
    const bob = try TestClient.init(aa, "bob", 25);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "stale-epoch",
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

    // A real Commit for epoch 1 -> 2.
    const c = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = alice.sig });
    defer c.deinit(gpa);
    try b.processCommit(.{ .commit_msg = c.commit });
    try expectSameEpoch(&a, &b);
    try testing.expectEqual(@as(u64, 2), b.epoch);

    // The SAME message again: `content.epoch == 1`, bob is at epoch 2. A
    // network that can replay a datagram can replay this. Must be
    // `error.WrongEpoch`, not a signature/MAC failure (those would still be
    // "safe", but for the wrong reason, and would not tell an implementer
    // that the epoch guard itself is what to fix if it ever regressed) and
    // never success.
    try testing.expectError(error.WrongEpoch, b.processCommit(.{ .commit_msg = c.commit }));
    try testing.expectEqual(@as(u64, 2), b.epoch);
}

// ── §12.4.3.2: external Commits ───────────────────────────────────────────
//
// **What anchors these, and what does not.** There is no external-Commit
// test vector in `mlswg/mls-implementations` at the pinned revision — the
// `passive-client-*.json` sessions never contain one — so unlike every
// Commit-processing claim in `kat_passive_test.zig`, nothing below is
// compared against another implementation. What replaces that, and the
// reason a half-built direction would have been worse than none, is that
// the two directions here are built from OPPOSITE halves of §8.3 and meet
// only at a value neither of them transports: an external joiner derives
// `init_secret` by `SetupBaseS` to the published `external_pub`, a member
// recovers it by `SetupBaseR` with `external_priv`, and the
// `epoch_authenticator` they are compared on is
// `DeriveSecret(epoch_secret, "authentication")` — downstream of that
// secret, of the tree hash, of the whole transcript and of a leaf index
// that appears nowhere on the wire. Two parties agreeing on it agree on
// every one of those.

/// A hostile external joiner: takes an external Commit this module built,
/// swaps the proposal list for `proposals`, and RE-SIGNS the result with
/// the joiner's own signature key.
///
/// The re-signing is what makes these tests reach §12.4.2's bullet 4 at
/// all. §6.1 verifies a `new_member_commit` with the key in
/// `commit.path.leaf_node` — a key the sender chooses — so an attacker
/// controls the signature completely and a receiver cannot reject a bad
/// proposal list by signature check. Simply corrupting the bytes would
/// fail at bullet 3 instead and prove nothing about the whitelist. The
/// `confirmation_tag` is left as it was: §12.4.2 checks it at bullet 12,
/// nine steps after the list, so a whitelist that works never gets there.
fn resignExternalCommit(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    commit_msg: []const u8,
    signer: TestSuite.Sig.KeyPair,
    old_gc: []const u8,
    proposals: []const content.ProposalOrRef,
) ![]u8 {
    return resignExternalCommitOpts(gpa, arena, commit_msg, signer, old_gc, proposals, false);
}

/// `drop_path` strips the `UpdatePath` — the one edit a joiner can make that
/// §12.4.3.2 forbids on its own ("External Commits MUST contain a path
/// field") rather than through §12.4's `needs_path` bookkeeping.
fn resignExternalCommitOpts(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    commit_msg: []const u8,
    signer: TestSuite.Sig.KeyPair,
    old_gc: []const u8,
    proposals: []const content.ProposalOrRef,
    drop_path: bool,
) ![]u8 {
    var r = codec.Reader.init(commit_msg);
    const msg = try framing.MLSMessage.decode(arena, &r);
    try testing.expect(r.atEnd());
    var pm = msg.public_message;
    var commit = pm.content.body.commit;
    commit.proposals = proposals;
    if (drop_path) commit.path = null;
    pm.content.body = .{ .commit = commit };

    const sig = try framing.signFramedContent(TestSuite, gpa, signer, .mls_public_message, pm.content, old_gc);
    const sig_bytes = sig.toBytes();
    pm.auth.signature = &sig_bytes;
    const out: framing.MLSMessage = .{ .public_message = pm };
    return out.encodeAlloc(gpa);
}

test "§12.4.3.2: a stranger turns a published GroupInfo into an external Commit, and every member lands in its epoch" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 31);
    const bob = try TestClient.init(aa, "bob", 32);
    const dave = try TestClient.init(aa, "dave", 33);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "external-join",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    var b = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
            // §12.4.3.2: "to join a group via an external Commit, a new
            // member needs a GroupInfo with an external_pub extension" —
            // and it is per-epoch, so it has to be asked for on the Commit
            // whose epoch will be published.
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try bob.join(gpa, c.welcome.?, &.{});
    };
    defer b.deinit();
    try expectSameEpoch(&a, &b);

    // The GroupInfo alice published for epoch 2 — the only thing dave has.
    // He was never added, no member did anything for him, and this object
    // is public.
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        try b.processCommit(.{ .commit_msg = c.commit });
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);
    try expectSameEpoch(&a, &b);

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    var d = joined.group;
    defer d.deinit();
    defer joined.messages.deinit(gpa);

    // §12.2's whitelist admits no Add, so there is nobody to welcome.
    try testing.expectEqual(@as(?[]u8, null), joined.messages.welcome);
    // §12.4.3.2: the sender type MUST be new_member_commit, and §6.2 gives
    // that sender no membership_tag field. Read off the wire, not off the
    // struct that produced it.
    {
        var r = codec.Reader.init(joined.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        try testing.expect(r.atEnd());
        try testing.expectEqual(framing.Sender.new_member_commit, msg.public_message.content.sender);
        try testing.expectEqual(@as(?[]const u8, null), msg.public_message.membership_tag);
        // "External Commits MUST contain a path field."
        try testing.expect(msg.public_message.content.body.commit.path != null);
    }

    // Dave was at epoch 3 before anybody else saw his Commit; the members
    // are still at epoch 2.
    try testing.expectEqual(@as(u64, 3), d.epoch);
    try testing.expectEqual(@as(u64, 2), a.epoch);

    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try b.processCommit(.{ .commit_msg = joined.messages.commit });

    // THE anchor: three parties, one of whom was a stranger a moment ago,
    // on the same `epoch_authenticator`. Dave computed his `init_secret`
    // with `SetupBaseS`; alice and bob recovered it with `SetupBaseR`; his
    // leaf index was never transmitted.
    try expectSameEpoch(&a, &b);
    try expectSameEpoch(&a, &d);

    // This is §12.4.1's OTHER leaf-assignment branch: alice and bob fill a
    // two-leaf tree, so there is no blank leaf and the tree is "expanded to
    // the right as defined in Section 7.7", which doubles it — dave takes
    // "the leftmost new blank leaf", index 2, and leaf 3 stays blank.
    try testing.expectEqual(@as(u32, 2), d.my_leaf_index);
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    try testing.expect(a.ratchet_tree.nodes[3 * 2] == null);

    // …and the group still works afterwards, in both directions: the
    // newcomer commits, and the founder processes it. An external join that
    // produced a state which cannot take another Commit would satisfy every
    // assertion above.
    {
        const c = try d.createCommit(gpa, .{ .io = io, .signature_key_pair = dave.sig });
        defer c.deinit(gpa);
        try a.processCommit(.{ .commit_msg = c.commit });
        try b.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &d);
        try expectSameEpoch(&b, &d);
    }
}

test "§12.4.1/§12.4.2: an external joiner lands in the LEFTMOST blank leaf, not the rightmost" {
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

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "leftmost",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    // alice=0, bob=1, carol=2 — a four-leaf tree whose leaf 3 is blank.
    var c_group = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .add = bob.kp } },
                .{ .by_value = .{ .add = carol.kp } },
            },
        });
        defer c.deinit(gpa);
        break :blk try carol.join(gpa, c.welcome.?, &.{});
    };
    defer c_group.deinit();
    try testing.expectEqual(@as(usize, 4), a.treeSize());

    // Remove bob. §7.7 truncates only TRAILING blanks and carol still holds
    // leaf 2, so the tree stays four leaves wide with TWO blanks in it —
    // leaf 1 and leaf 3. That is the shape that can tell the RFC's rule
    // ("the leftmost blank leaf node") apart from any other rule that also
    // finds a free slot.
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 1 } }},
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        try c_group.processCommit(.{ .commit_msg = c.commit });
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    try testing.expect(a.ratchet_tree.nodes[1 * 2] == null);
    try testing.expect(a.ratchet_tree.nodes[3 * 2] == null);

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    var d = joined.group;
    defer d.deinit();
    defer joined.messages.deinit(gpa);

    // The sender's own view…
    try testing.expectEqual(@as(u32, 1), d.my_leaf_index);
    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try c_group.processCommit(.{ .commit_msg = joined.messages.commit });
    try expectSameEpoch(&a, &d);
    try expectSameEpoch(&a, &c_group);

    // …and every receiver's, computed independently. A rule that picked
    // the rightmost blank would put dave at leaf 3 on BOTH sides and the
    // round trip above would still pass — which is exactly why this
    // assertion names the index rather than only comparing the two views.
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    const dave_leaf = a.ratchet_tree.nodes[1 * 2].?.leaf;
    try testing.expectEqualStrings("dave", dave_leaf.credential.basic);
    try testing.expect(a.ratchet_tree.nodes[3 * 2] == null);
}

test "§12.2: an external Commit's proposal list is a WHITELIST, and a receiver enforces it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 51);
    const dave = try TestClient.init(aa, "dave", 52);
    const mallory = try TestClient.init(aa, "mallory", 53);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "whitelist",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    // A well-formed external Commit, to be spoiled four ways.
    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    joined.group.deinit();
    defer joined.messages.deinit(gpa);

    const old_gc = try a.groupContextAlloc(gpa);
    defer gpa.free(old_gc);
    const ext_init: content.ProposalOrRef = blk: {
        var r = codec.Reader.init(joined.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        break :blk msg.public_message.content.body.commit.proposals[0];
    };

    const cases = [_]struct {
        want: anyerror,
        proposals: []const content.ProposalOrRef,
    }{
        // "No other proposals" — an Add is the interesting one, because it
        // is the proposal a regular Commit's blacklist happily accepts, and
        // it is how a stranger would smuggle a member in.
        .{
            .want = error.ProposalNotAllowedInExternalCommit,
            .proposals = &.{ ext_init, .{ .proposal = .{ .add = mallory.kp } } },
        },
        // "Exactly one ExternalInit" — none.
        .{ .want = error.MissingExternalInit, .proposals = &.{} },
        // "Exactly one ExternalInit" — two.
        .{ .want = error.MultipleExternalInit, .proposals = &.{ ext_init, ext_init } },
        // "At most one Remove proposal".
        .{
            .want = error.MultipleRemoveInExternalCommit,
            .proposals = &.{ ext_init, .{ .proposal = .{ .remove = 7 } }, .{ .proposal = .{ .remove = 8 } } },
        },
    };
    for (cases) |c| {
        const bad = try resignExternalCommit(gpa, aa, joined.messages.commit, dave.sig, old_gc, c.proposals);
        defer gpa.free(bad);
        try testing.expectError(c.want, a.processCommit(.{ .commit_msg = bad }));
        // Every one of these is refused at §12.4.2's bullet 4, before the
        // tree is touched — so the group is not poisoned and still works.
        try testing.expectEqual(@as(u64, 1), a.epoch);
        try testing.expect(!a.poisoned);
    }

    // §12.4.3.2's "MUST NOT include any proposals by reference". A
    // `ProposalRef` that resolves to nothing fails earlier, at resolution,
    // so the one that reaches the whitelist has to name a real proposal —
    // here one alice herself published this epoch.
    {
        const p_msg = try a.createProposal(gpa, .{
            .signature_key_pair = alice.sig,
            .proposal = .{ .remove = 0 },
        });
        defer gpa.free(p_msg);
        const ref = blk: {
            var r = codec.Reader.init(p_msg);
            const m = try framing.MLSMessage.decode(aa, &r);
            const rf = try framing.proposalRef(TestSuite, gpa, m.public_message.authenticatedContent());
            break :blk try aa.dupe(u8, &rf);
        };
        const bad = try resignExternalCommit(gpa, aa, joined.messages.commit, dave.sig, old_gc, &.{
            ext_init,
            .{ .reference = ref },
        });
        defer gpa.free(bad);
        try testing.expectError(
            error.ProposalByReferenceInExternalCommit,
            a.processCommit(.{ .commit_msg = bad, .proposal_msgs = &.{p_msg} }),
        );
        try testing.expectEqual(@as(u64, 1), a.epoch);
    }

    // The unspoiled Commit is still accepted, which is what makes the four
    // refusals above about the list and not about the fixture.
    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try testing.expectEqual(@as(u64, 2), a.epoch);
}

test "§6.2: a new_member_commit PublicMessage has no membership_tag field, and neither half of that is assumed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 61);
    const dave = try TestClient.init(aa, "dave", 62);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "no-tag",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    joined.group.deinit();
    defer joined.messages.deinit(gpa);

    // On the WIRE: §6.2's `select` gives this sender no tag field, so a tag
    // appended to the message is not a tag at all — it is trailing input,
    // and `processCommit` refuses to decode a message it has bytes left
    // over from. (Silently ignoring them would let a Delivery Service pad
    // handshake messages undetectably.)
    {
        const padded = try gpa.alloc(u8, joined.messages.commit.len + 33);
        defer gpa.free(padded);
        @memcpy(padded[0..joined.messages.commit.len], joined.messages.commit);
        padded[joined.messages.commit.len] = 32; // varint length prefix
        @memset(padded[joined.messages.commit.len + 1 ..], 0xAA);
        try testing.expectError(error.Malformed, a.processCommit(.{ .commit_msg = padded }));
    }

    // In the STRUCT: the guard `processCommit` runs before it trusts
    // anything else about an external Commit. Driven directly because no
    // decode path can produce this value — see
    // `rejectExternalCommitFraming`'s doc comment for why it exists anyway.
    {
        var r = codec.Reader.init(joined.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        var pm = msg.public_message;
        try rejectExternalCommitFraming(pm); // as decoded: no tag, accepted
        pm.membership_tag = &[_]u8{0} ** 32;
        try testing.expectError(error.UnexpectedMembershipTag, rejectExternalCommitFraming(pm));
    }

    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try testing.expectEqual(@as(u64, 2), a.epoch);
}

test "§12.4.3.2: an external Commit with no path is refused by its OWN rule, not by §12.4's needs_path" {
    // §12.4.3.2 states two rules that happen to coincide today: "External
    // Commits MUST contain a path field", and §12.4's `needs_path`, which
    // lists `external_init` among the proposal types that require one. They
    // are independent — only the first is unconditional — and a receiver
    // that leaned on the second would still pass every other test here.
    //
    // So this test pins the DISTINCT error. Without it, replacing
    // `error.ExternalCommitRequiresPath` with the generic
    // `error.PathRequired` changes nothing that any test can see, and the
    // unconditional rule quietly becomes an accident of proposal typing.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const aa = arena_state.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const alice = try TestClient.init(aa, "alice", 61);
    const dave = try TestClient.init(aa, "dave", 62);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "external-path-rule",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    joined.group.deinit();
    defer joined.messages.deinit(gpa);

    const old_gc = try a.groupContextAlloc(gpa);
    defer gpa.free(old_gc);
    const ext_init: content.ProposalOrRef = blk: {
        var r = codec.Reader.init(joined.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        break :blk msg.public_message.content.body.commit.proposals[0];
    };

    // The proposal list stays legal — only the path is removed — so nothing
    // in the whitelist can be what rejects this.
    const pathless = try resignExternalCommitOpts(gpa, aa, joined.messages.commit, dave.sig, old_gc, &.{ext_init}, true);
    defer gpa.free(pathless);

    try testing.expectError(error.ExternalCommitRequiresPath, a.processCommit(.{
        .commit_msg = pathless,
    }));
    // Refused before anything was mutated: the group is untouched.
    try testing.expect(!a.poisoned);
    try testing.expectEqual(@as(u64, 1), a.epoch);
}

test "§12.4.3.2: joinByExternalCommit refuses what a receiver would, and refuses a GroupInfo it cannot use" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 71);
    const dave = try TestClient.init(aa, "dave", 72);
    const mallory = try TestClient.init(aa, "mallory", 73);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "sender-refusals",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    // §12.4.3.2: a GroupInfo WITHOUT `external_pub` cannot be joined
    // against — §8.3 has nothing to encapsulate to. This is the default
    // shape of a GroupInfo, so the refusal has to be explicit.
    {
        const c = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = alice.sig });
        defer c.deinit(gpa);
        try testing.expectError(error.ExternalPubUnavailable, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = c.group_info,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
        }));
    }

    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    // §12.2 opens with "A group member creating a Commit AND a group member
    // processing a Commit MUST verify" — so the sender runs the same
    // whitelist, and a caller that asks for a forbidden proposal is told so
    // rather than handed bytes nobody will accept.
    try testing.expectError(
        error.ProposalNotAllowedInExternalCommit,
        Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = published_gi,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
            .proposals = &.{.{ .add = mallory.kp }},
        }),
    );
    // The ExternalInit is contributed by `joinByExternalCommit` itself, so
    // a caller supplying one asks for two.
    try testing.expectError(
        error.MultipleExternalInit,
        Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = published_gi,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
            .proposals = &.{.{ .external_init = &[_]u8{0xaa} ** 32 }},
        }),
    );

    // A GroupInfo whose signature does not verify is refused before any of
    // it is believed — the joiner has no other reason to trust its
    // tree_hash, its epoch or its external_pub.
    {
        const bad = try gpa.dupe(u8, published_gi);
        defer gpa.free(bad);
        bad[bad.len - 1] ^= 0x01;
        try testing.expectError(error.SignatureVerificationFailed, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = bad,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
        }));
    }

    // …and the good one still works, so none of the above was a fixture
    // problem.
    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    defer joined.group.deinit();
    defer joined.messages.deinit(gpa);
    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try expectSameEpoch(&a, &joined.group);
}

// ── §8.4 resumption PSKs on the §12.4.3.2 external-join path ──────────────
//
// What these tests can and cannot anchor, stated before the first one so it
// is not implied by omission:
//
//   * §8.4's `psk_secret` ladder — the `PSKLabel`, the "derived psk" label,
//     the index/count binding and therefore its ORDER sensitivity — is
//     pinned byte-exact by `psk_secret.json` for chains of 1 to 10 PSKs, in
//     `kat_keyschedule_test.zig`. That is an EXTERNAL anchor and nothing
//     here re-proves it.
//   * every `PreSharedKeyID` in every vector this repo carries
//     (`psk_secret.json`, `messages.json`, `passive-client-*.json`) has
//     `psktype = external(1)`. The RESUMPTION arm — its lookup rules, its
//     `usage`/`psk_group_id`/`psk_epoch` semantics — has NO external vector
//     anywhere. What replaces one below is not a round trip: the joiner
//     resolves the PSK from a value handed to it by its caller while every
//     member resolves the SAME `PreSharedKeyID` from its own remembered
//     `resumption_history`, by different code on a different path, and the
//     two must agree or the `confirmation_tag` fails. A rule applied wrongly
//     but consistently on both sides is exactly what that catches.

/// The `resumption_psk` a group holds for one epoch it lived through — what
/// a client would have kept in storage before losing the rest of its state.
fn rememberedResumptionPsk(g: *const Group(TestSuite), epoch: u64) ![TestSuite.Nh]u8 {
    for (g.resumption_history.items) |h| {
        if (h.epoch == epoch) return h.secret;
    }
    return error.TestExpectedEqual;
}

fn resumptionId(
    usage: keyschedule.ResumptionPskUsage,
    group_id: []const u8,
    epoch: u64,
    nonce: []const u8,
) keyschedule.PreSharedKeyId {
    return .{
        .id = .{ .resumption = .{ .usage = usage, .psk_group_id = group_id, .psk_epoch = epoch } },
        .psk_nonce = nonce,
    };
}

test "§12.4.3.2/§8.4: a resyncing joiner resolves a resumption PSK the CALLER supplied, and every member resolves the same id from its own history" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 81);
    const bob = try TestClient.init(aa, "bob", 82);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "resync-group",
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
    try expectSameEpoch(&a, &b);
    try testing.expectEqual(@as(u64, 1), b.epoch);
    try testing.expectEqual(@as(u32, 1), b.my_leaf_index);

    // The premise, made explicit rather than assumed: alice and bob derived
    // the SAME `resumption_psk` for epoch 1, because §8's chain is the
    // group's, not the member's. Bob keeps his copy; that is the only thing
    // he will still have after losing his state.
    const kept = try rememberedResumptionPsk(&b, 1);
    try testing.expectEqualSlices(u8, &(try rememberedResumptionPsk(&a, 1)), &kept);

    // Alice publishes a GroupInfo for epoch 2 — what a Delivery Service
    // caches, and all a resyncing client has to work from.
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        try b.processCommit(.{ .commit_msg = c.commit });
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);
    try expectSameEpoch(&a, &b);

    // §12.4.3.2's "resync" flavor: bob commits himself back in and removes
    // his own prior appearance, gating it on a resumption PSK that only a
    // client present at epoch 1 could hold. Usage `application`, NOT
    // `reinit` — see `validatePskProposal` for why the RFC's own wording
    // here cannot be followed literally.
    const nonce = [_]u8{0x77} ** TestSuite.Nh;
    const proposals = [_]content.Proposal{
        .{ .psk = resumptionId(.application, "resync-group", 1, &nonce) },
        .{ .remove = 1 },
    };

    // Before the feature this test exists for: the same call with nothing
    // handed in cannot resolve the id, because a group entered by external
    // Commit has an EMPTY `resumption_history`.
    try testing.expectError(error.PskNotAvailable, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = bob.kp_msg,
        .signature_key_pair = bob.sig,
        .proposals = &proposals,
    }));

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = bob.kp_msg,
        .signature_key_pair = bob.sig,
        .proposals = &proposals,
        .resumption_psks = &.{.{
            .usage = .application,
            .group_id = "resync-group",
            .epoch = 1,
            .secret = &kept,
        }},
    });
    var b2 = joined.group;
    defer b2.deinit();
    defer joined.messages.deinit(gpa);

    // THE anchor. Alice never saw `kept`; she resolves the same
    // `PreSharedKeyID` out of her own `resumption_history` by a different
    // branch of `resolvePsksFromIds`, chains it through §8.4 at the same
    // position, and lands on the same `epoch_authenticator`. A `psk_secret`
    // that differed by one bit would fail her `confirmation_tag` instead.
    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try expectSameEpoch(&a, &b2);

    // …and it was really the PSK doing work, not a no-op: the same Commit
    // shape with NO PreSharedKey proposal lands on a different epoch secret.
    // (Different transcript too, hence the narrower assertion — what is
    // being ruled out is a `psk_secret` that stayed all-zero.)
    try testing.expectEqual(@as(u32, 1), b2.my_leaf_index);
    try testing.expectEqual(@as(usize, 2), a.treeSize());
    try testing.expect(!std.mem.eql(u8, &a.epochAuthenticator(), &[_]u8{0} ** TestSuite.Nh));

    // The group still works: the resynced member commits, the founder
    // follows. A join that produced state which cannot take another Commit
    // would satisfy everything above.
    {
        const c = try b2.createCommit(gpa, .{ .io = io, .signature_key_pair = bob.sig });
        defer c.deinit(gpa);
        try a.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &b2);
    }
}

test "§8.4: a resumption PreSharedKeyID naming ANOTHER group does not resolve to this group's epoch" {
    // The mutation this exists for is the one that hides: drop `psk_group_id`
    // from the lookup and match on `psk_epoch` alone. Both the sender and
    // every receiver then apply the same wrong rule to the same id, derive
    // the same `psk_secret` from the same bytes, and the Commit is
    // ACCEPTED — every round-trip assertion in this file stays green while
    // an attacker-chosen `psk_group_id` silently resolves to our own secret.
    // What breaks the symmetry is that the joiner's authorization is
    // caller-supplied and the members' is not.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 83);
    const dave = try TestClient.init(aa, "dave", 84);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "our-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);
    try testing.expectEqual(@as(u64, 1), a.epoch);

    // Alice's epoch-1 secret — the value an epoch-only lookup would hand
    // back for ANY `psk_group_id`. The joiner supplies exactly it, so the
    // two sides cannot be told apart by the bytes.
    const alice_epoch1 = try rememberedResumptionPsk(&a, 1);
    const nonce = [_]u8{0x11} ** TestSuite.Nh;

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
        .proposals = &.{.{ .psk = resumptionId(.application, "some-other-group", 1, &nonce) }},
        .resumption_psks = &.{.{
            .usage = .application,
            .group_id = "some-other-group",
            .epoch = 1,
            .secret = &alice_epoch1,
        }},
    });
    defer joined.group.deinit();
    defer joined.messages.deinit(gpa);

    // The joiner accepts it: its caller authorized that exact triple, and
    // this module does not pretend to know whether "some-other-group" epoch
    // 1 is real.
    try testing.expectEqual(@as(u64, 2), joined.group.epoch);

    // Alice must NOT. Her history is her own group's; nothing in it answers
    // to `psk_group_id = "some-other-group"`, however well the epoch number
    // lines up.
    try testing.expectError(error.PskNotAvailable, a.processCommit(.{
        .commit_msg = joined.messages.commit,
    }));
    try testing.expectEqual(@as(u64, 1), a.epoch);
    // PSK resolution happens inside §12.3's application step, i.e. after the
    // tree may already have been touched — so the refusal poisons rather
    // than rewinds. That is this module's documented atomicity, pinned here
    // because it is what stops the next assertion from being written against
    // a group that quietly carried on. The receiver-side epoch component of
    // the same lookup is pinned directly in the positional-resolution test
    // below, where it needs no second group to observe.
    try testing.expect(a.poisoned);
}

test "§8.4: a caller-supplied resumption PSK matches on the WHOLE PreSharedKeyID triple, usage included" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 85);
    const bob = try TestClient.init(aa, "bob", 86);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "triple",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    const real = try rememberedResumptionPsk(&a, 1);
    const garbage = [_]u8{0xee} ** TestSuite.Nh;
    const nonce = [_]u8{0x22} ** TestSuite.Nh;

    // Two entries for the SAME group and epoch, differing only in `usage`
    // and carrying different secrets — the wrong one first. §8.4 puts the
    // whole `PreSharedKeyID` (usage and all) into the `PSKLabel`, so picking
    // the wrong entry is not "the same either way": it yields a different
    // `psk_secret` and alice, who resolves the id from her own history,
    // rejects the Commit. A matcher that ignored `usage` takes the first.
    const supplied = [_]ResumptionPsk{
        .{ .usage = @enumFromInt(7), .group_id = "triple", .epoch = 1, .secret = &garbage },
        .{ .usage = .application, .group_id = "triple", .epoch = 1, .secret = &real },
    };

    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = bob.kp_msg,
        .signature_key_pair = bob.sig,
        .proposals = &.{.{ .psk = resumptionId(.application, "triple", 1, &nonce) }},
        .resumption_psks = &supplied,
    });
    defer joined.group.deinit();
    defer joined.messages.deinit(gpa);
    try a.processCommit(.{ .commit_msg = joined.messages.commit });
    try expectSameEpoch(&a, &joined.group);

    // The epoch component of the triple, on its own: an entry for epoch 1
    // does not answer an id naming epoch 0.
    try testing.expectError(error.PskNotAvailable, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = bob.kp_msg,
        .signature_key_pair = bob.sig,
        .proposals = &.{.{ .psk = resumptionId(.application, "triple", 0, &nonce) }},
        .resumption_psks = &.{.{
            .usage = .application,
            .group_id = "triple",
            .epoch = 1,
            .secret = &real,
        }},
    }));

    // §8.4: a resumption PSK IS a `resumption_psk`, so it is `KDF.Nh` wide.
    // Rejected over the whole list, whether or not this Commit names it.
    try testing.expectError(error.WrongSecretLength, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = bob.kp_msg,
        .signature_key_pair = bob.sig,
        .resumption_psks = &.{.{
            .usage = .application,
            .group_id = "triple",
            .epoch = 1,
            .secret = real[0 .. TestSuite.Nh - 1],
        }},
    }));
}

test "§12.1.4: a PreSharedKey proposal with usage reinit or branch is invalid, and so is a short psk_nonce" {
    // §12.1.4's own three conditions. The reinit/branch pair is the one
    // §12.4.3.2's closing paragraph appears to recommend for gating a
    // resync; §12.1.4 and §11.2/§11.3 are normative and say otherwise, so
    // both the sender and the receiver refuse it here. Pinned because a
    // silent acceptance is invisible: the Commit would go through and only
    // a stricter peer would ever complain.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 87);
    const dave = try TestClient.init(aa, "dave", 88);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "usage-rules",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try gpa.dupe(u8, c.group_info);
    };
    defer gpa.free(published_gi);

    const secret = try rememberedResumptionPsk(&a, 1);
    const nonce = [_]u8{0x33} ** TestSuite.Nh;
    const short_nonce = [_]u8{0x33} ** (TestSuite.Nh - 1);

    // ── the SENDER's half: §12.2 opens with "A group member creating a
    // Commit AND a group member processing a Commit MUST verify", so a
    // caller asking for one of these is told so rather than handed bytes
    // nobody will accept.
    const bad = [_]struct { want: anyerror, usage: keyschedule.ResumptionPskUsage, id: keyschedule.PreSharedKeyId }{
        .{ .want = error.ResumptionPskUsageNotAllowed, .usage = .reinit, .id = resumptionId(.reinit, "usage-rules", 1, &nonce) },
        .{ .want = error.ResumptionPskUsageNotAllowed, .usage = .branch, .id = resumptionId(.branch, "usage-rules", 1, &nonce) },
        .{ .want = error.PskNonceLength, .usage = .application, .id = .{ .id = .{ .external = "x" }, .psk_nonce = &short_nonce } },
        .{ .want = error.PskNonceLength, .usage = .application, .id = resumptionId(.application, "usage-rules", 1, short_nonce[0..]) },
    };
    for (bad, 0..) |c, i| {
        errdefer std.debug.print("case {d}\n", .{i});
        // Every case is supplied the key material it names, so the refusal
        // can only be §12.1.4's rule and never `error.PskNotAvailable`.
        const supplied = [_]ResumptionPsk{.{
            .usage = c.usage,
            .group_id = "usage-rules",
            .epoch = 1,
            .secret = &secret,
        }};
        // The external-join path, through §12.2's whitelist.
        try testing.expectError(c.want, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = published_gi,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
            .proposals = &.{.{ .psk = c.id }},
            .external_psks = &.{.{ .psk_id = "x", .psk = "k" }},
            .resumption_psks = &supplied,
        }));
        // …and a REGULAR Commit, through §12.2's other procedure. §12.1.4 is
        // stated about the proposal, so both procedures owe it.
        try testing.expectError(c.want, a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .psk = c.id } }},
            .external_psks = &.{.{ .psk_id = "x", .psk = "k" }},
        }));
    }

    // ── the RECEIVER's half, for the reinit case: a peer that followed
    // §12.4.3.2's advice literally produces a Commit alice must refuse. The
    // list is otherwise legal — one ExternalInit, one PreSharedKey — so
    // nothing in the whitelist can be what rejects it.
    var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = published_gi,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    });
    joined.group.deinit();
    defer joined.messages.deinit(gpa);

    const old_gc = try a.groupContextAlloc(gpa);
    defer gpa.free(old_gc);
    const ext_init: content.ProposalOrRef = blk: {
        var r = codec.Reader.init(joined.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        break :blk msg.public_message.content.body.commit.proposals[0];
    };
    const forged = try resignExternalCommit(gpa, aa, joined.messages.commit, dave.sig, old_gc, &.{
        ext_init,
        .{ .proposal = .{ .psk = resumptionId(.reinit, "usage-rules", 1, &nonce) } },
    });
    defer gpa.free(forged);
    try testing.expectError(error.ResumptionPskUsageNotAllowed, a.processCommit(.{ .commit_msg = forged }));
    // Refused before anything was mutated.
    try testing.expect(!a.poisoned);
    try testing.expectEqual(@as(u64, 1), a.epoch);
}

test "§8.4: PSKs resolve POSITIONALLY — out[i] is the resolution of ids[i] and of nothing else" {
    // §8.4's `PSKLabel` binds each PSK to its index, so a resolver that
    // grouped by `psktype` or reversed would produce a wrong `psk_secret` —
    // and would produce the SAME wrong one on every side, so no round trip
    // could see it. This asserts the mapping directly instead.
    //
    // For EXTERNAL PSKs that guarantee turns out to be externally anchored
    // already, which was worth finding out rather than assuming: filling
    // `out` back-to-front while leaving `ids` alone also fails
    // `passive-client-handling-commit.json`, so at least one recorded
    // session commits two or more PSKs at once and the vector notices the
    // permutation. What this test adds is the same guarantee for a MIXED
    // list that includes the RESUMPTION arm — which no vector this repo
    // carries exercises at all — and the two negative lookups below, which
    // are a member's own history rules and have no vector either.
    const gpa = testing.allocator;
    const G = Group(TestSuite);

    const nonce = [_]u8{0x44} ** TestSuite.Nh;
    const from_history = [_]u8{0xa1} ** TestSuite.Nh;
    const from_caller = [_]u8{0xa2} ** TestSuite.Nh;

    const ids = [_]keyschedule.PreSharedKeyId{
        .{ .id = .{ .external = "first" }, .psk_nonce = &nonce },
        resumptionId(.application, "mine", 4, &nonce),
        .{ .id = .{ .external = "second" }, .psk_nonce = &nonce },
        resumptionId(.application, "elsewhere", 9, &nonce),
    };
    const external = [_]ExternalPsk{
        .{ .psk_id = "second", .psk = "SECOND" },
        .{ .psk_id = "first", .psk = "FIRST" },
    };
    const history = [_]G.ResumptionEntry{
        .{ .epoch = 3, .secret = @splat(0xff) },
        .{ .epoch = 4, .secret = from_history },
    };
    const supplied = [_]ResumptionPsk{
        .{ .usage = .application, .group_id = "elsewhere", .epoch = 9, .secret = &from_caller },
    };

    const out = try G.resolvePsksFromIds(gpa, &ids, &external, .{
        .group_id = "mine",
        .history = &history,
        .supplied = &supplied,
    });
    defer gpa.free(out);

    try testing.expectEqual(@as(usize, 4), out.len);
    try testing.expectEqualSlices(u8, "FIRST", out[0].secret);
    try testing.expectEqualSlices(u8, &from_history, out[1].secret);
    try testing.expectEqualSlices(u8, "SECOND", out[2].secret);
    try testing.expectEqualSlices(u8, &from_caller, out[3].secret);
    // The id travels with its secret — `pskSecret` reads it back out for the
    // `PSKLabel`, so a slot carrying the right key under the wrong id would
    // be just as wrong.
    for (out, ids) |got, want| {
        try testing.expectEqual(want.psk_nonce.ptr, got.id.psk_nonce.ptr);
        try testing.expectEqual(@as(keyschedule.PskType, want.pskType()), got.id.pskType());
    }

    // The group's OWN history wins over a caller-supplied entry naming the
    // same triple: a caller cannot shadow a secret this group derived.
    const shadow = [_]ResumptionPsk{
        .{ .usage = .application, .group_id = "mine", .epoch = 4, .secret = &from_caller },
    };
    const out2 = try G.resolvePsksFromIds(gpa, ids[1..2], &.{}, .{
        .group_id = "mine",
        .history = &history,
        .supplied = &shadow,
    });
    defer gpa.free(out2);
    try testing.expectEqualSlices(u8, &from_history, out2[0].secret);

    // Both halves of a resumption PSK's identity, against a group's OWN
    // history and with nothing supplied — the lookup a MEMBER performs when
    // it receives somebody else's Commit, and the one that has no
    // caller-supplied value to disagree with. An epoch this group never
    // lived through, and this group's own epoch under somebody else's
    // `psk_group_id`, must both be refused; the second is the one an
    // epoch-only lookup would happily answer.
    const refuse = [_]keyschedule.PreSharedKeyId{
        resumptionId(.application, "mine", 5, &nonce),
        resumptionId(.application, "not-mine", 4, &nonce),
    };
    for (refuse, 0..) |id, i| {
        errdefer std.debug.print("refuse case {d}\n", .{i});
        try testing.expectError(error.PskNotAvailable, G.resolvePsksFromIds(gpa, &.{id}, &.{}, .{
            .group_id = "mine",
            .history = &history,
        }));
    }
}

// ── §12.4.3.1: the third tree-integrity bullet, on a HANDED tree ──────────

test "§12.4.3.1: a joiner refuses a handed ratchet tree whose leaf signatures do not verify" {
    // Regression for the "forged roster" defect: the joiner ran
    // `verifyTreeHash`, `validateParentHashes` and the `GroupInfo`
    // signature and then trusted every leaf. All three are computed and
    // signed by the party that HANDS the tree over, so none of them says
    // anything about who the other leaves belong to — only each leaf's own
    // `LeafNodeTBS` signature binds a `Credential` to a key its owner
    // actually holds.
    //
    // Alice is the attacker here: she publishes a `GroupInfo` for a group
    // that really exists, but rewrites bob's leaf to claim a different
    // identity, leaving bob's (now wrong) signature on it. She then
    // recomputes the tree hash over her forgery and re-signs the whole
    // `GroupInfo`, so the forgery is perfect everywhere except the one
    // place she cannot forge.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 91);
    const bob = try TestClient.init(aa, "bob", 92);
    const dave = try TestClient.init(aa, "dave", 93);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "forged-roster",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try aa.dupe(u8, c.group_info);
    };

    // Non-vacuity: the honest `GroupInfo` this forgery is built from really
    // does admit a stranger. Whatever the forged one is rejected for, it is
    // not a broken fixture.
    {
        var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = published_gi,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
        });
        joined.group.deinit();
        joined.messages.deinit(gpa);
    }

    var gi_reader = codec.Reader.init(published_gi);
    const gi_msg = try framing.MLSMessage.decode(aa, &gi_reader);
    try testing.expect(gi_reader.atEnd());
    const gi = gi_msg.group_info;

    // The forged tree. Bob's leaf keeps his signature_key, his
    // encryption_key and his signature; only the identity the application
    // will be shown changes, so his `LeafNodeTBS` signature no longer
    // covers it.
    //
    // The forged leaf is seated under a BLANK parent, because §7.9.2's
    // per-parent "exactly one descendant" check hashes the sibling
    // subtree's TREE hash — a non-blank parent would therefore catch a
    // rewritten leaf below it as a side effect, and this test would then
    // pass without the leaf-signature check existing at all. A blank
    // parent is not a contrivance: it is what an Add-only Commit (no
    // `UpdatePath`) leaves behind, so this is the tree shape a real
    // welcomer really can hand over.
    var t = try gi.ratchetTree(aa);
    var bob_leaf = t.nodes[2].?.leaf;
    try testing.expectEqualSlices(u8, "bob", bob_leaf.credential.basic);
    bob_leaf.credential = .{ .basic = "ceo@example.com" };
    t.nodes[1] = null;
    t.nodes[2] = .{ .leaf = bob_leaf };

    // Recompute the two things a receiver checks over the tree itself...
    const forged_tree_bytes = try t.encode(aa);
    const forged_root = try treehash.rootHash(TestSuite, aa, &t);

    const forged_exts = try aa.alloc(tree.Extension, gi.extensions.len);
    var replaced_tree_ext = false;
    for (gi.extensions, forged_exts) |src, *dst| {
        dst.* = src;
        if (src.extension_type == welcome_mod.extension_type_ratchet_tree) {
            dst.extension_data = forged_tree_bytes;
            replaced_tree_ext = true;
        }
    }
    try testing.expect(replaced_tree_ext);

    var forged_gc = gi.group_context;
    forged_gc.tree_hash = &forged_root;
    var forged: welcome_mod.GroupInfo = .{
        .group_context = forged_gc,
        .extensions = forged_exts,
        .confirmation_tag = gi.confirmation_tag,
        .signer = gi.signer,
        .signature = &.{},
    };
    // ...and re-sign, as the attacker who owns the signer leaf can.
    forged.signature = try aa.dupe(u8, &(try forged.sign(TestSuite, aa, alice.sig)).toBytes());

    // The forgery really is perfect except for the leaf signature: every
    // check that existed before this regression accepts it. Without this
    // block the expectError below could be passing for the wrong reason.
    {
        var check_tree = try forged.ratchetTree(aa);
        try welcome_mod.verifyTreeHash(TestSuite, gpa, &check_tree, forged.group_context);
        try treekem.validateParentHashes(TestSuite, gpa, &check_tree);
        const signer_key = try leafSignatureKey(&check_tree, forged.signer);
        try forged.verifySignature(TestSuite, gpa, signer_key);
        // And the leaf itself is exactly what the joiner must catch.
        try testing.expectError(
            error.SignatureVerificationFailed,
            check_tree.nodes[2].?.leaf.verifySignature(TestSuite, gpa, forged.group_context.group_id, 1),
        );
    }

    const forged_msg: framing.MLSMessage = .{ .group_info = forged };
    const forged_bytes = try forged_msg.encodeAlloc(aa);

    try testing.expectError(error.SignatureVerificationFailed, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = forged_bytes,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    }));
}

// ── §12.4.3.1 / §6: the protocol version is not decoration ────────────────

test "§6: MLSMessage.decode refuses a version it does not implement" {
    // Regression: the outer wire door read `ProtocolVersion` and threw it
    // away, so bytes announcing any version at all were parsed as MLS 1.0.
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 94);

    // Non-vacuity: unmodified, this exact buffer decodes.
    {
        var r = codec.Reader.init(alice.kp_msg);
        const msg = try framing.MLSMessage.decode(aa, &r);
        try testing.expect(r.atEnd());
        try testing.expect(msg == .key_package);
    }

    // `MLSMessage`'s first field is `ProtocolVersion`, a uint16 — RFC 9420
    // §6's struct order, and §17.1's Table 7 gives `mls10` the value 1.
    try testing.expectEqual(@as(u8, 0), alice.kp_msg[0]);
    try testing.expectEqual(@as(u8, 1), alice.kp_msg[1]);

    for ([_]u16{ 0, 2, 0x0999, 0xffff }) |v| {
        errdefer std.debug.print("version 0x{x:0>4}\n", .{v});
        const forged = try aa.dupe(u8, alice.kp_msg);
        std.mem.writeInt(u16, forged[0..2], v, .big);
        var r = codec.Reader.init(forged);
        try testing.expectError(error.UnsupportedProtocolVersion, framing.MLSMessage.decode(aa, &r));
    }
}

test "§12.4.3.1: a joiner refuses a group whose GroupContext declares a version it does not implement" {
    // Regression: `GroupContext.version` was decoded, stored, mixed into
    // the key schedule — and never compared to anything, one line away
    // from the cipher-suite check that WAS made. The field is inside the
    // signed `GroupInfoTBS`, so the attacker here is the welcomer itself:
    // it declares a version, re-signs, and the joiner used to operate the
    // group as MLS 1.0 regardless.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 95);
    const dave = try TestClient.init(aa, "dave", 96);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "wrong-version",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    const published_gi = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .include_external_pub = true,
        });
        defer c.deinit(gpa);
        break :blk try aa.dupe(u8, c.group_info);
    };

    // Non-vacuity: the honest GroupInfo admits a stranger.
    {
        var joined = try Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
            .io = io,
            .group_info_msg = published_gi,
            .key_package_msg = dave.kp_msg,
            .signature_key_pair = dave.sig,
        });
        joined.group.deinit();
        joined.messages.deinit(gpa);
    }

    var gi_reader = codec.Reader.init(published_gi);
    const gi_msg = try framing.MLSMessage.decode(aa, &gi_reader);
    try testing.expect(gi_reader.atEnd());
    const gi = gi_msg.group_info;
    try testing.expectEqual(keyschedule.ProtocolVersion.mls10, gi.group_context.version);

    var forged_gc = gi.group_context;
    forged_gc.version = @enumFromInt(0x0999);
    var forged: welcome_mod.GroupInfo = .{
        .group_context = forged_gc,
        .extensions = gi.extensions,
        .confirmation_tag = gi.confirmation_tag,
        .signer = gi.signer,
        .signature = &.{},
    };
    forged.signature = try aa.dupe(u8, &(try forged.sign(TestSuite, aa, alice.sig)).toBytes());

    // Everything else about it is intact — the GroupInfo signature over the
    // rewritten context verifies, so the rejection below is the version
    // check and nothing else.
    {
        var check_tree = try forged.ratchetTree(aa);
        try welcome_mod.verifyTreeHash(TestSuite, gpa, &check_tree, forged.group_context);
        const signer_key = try leafSignatureKey(&check_tree, forged.signer);
        try forged.verifySignature(TestSuite, gpa, signer_key);
    }

    const forged_msg: framing.MLSMessage = .{ .group_info = forged };
    const forged_bytes = try forged_msg.encodeAlloc(aa);

    try testing.expectError(error.UnsupportedProtocolVersion, Group(TestSuite).joinByExternalCommit(gpa, gpa, .{
        .io = io,
        .group_info_msg = forged_bytes,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = dave.sig,
    }));
}
