// SPDX-License-Identifier: MIT

//! RFC 9420 §9 — the application-message layer, written from OUTSIDE the
//! library.
//!
//! **Why this file exists at all.** `mls.Group` deliberately does not own it,
//! and says so in its own doc comment: "`secrettree.zig` owns §9's ratchets,
//! but this object does not drive them: a Commit changes `encryption_secret`,
//! and re-keying the secret tree per epoch is a separate concern with its own
//! generation/deletion policy." That is a defensible boundary — the deletion
//! policy really is the application's — but it means a chat client has to
//! assemble the send path and the receive path itself, out of public parts.
//! This file is that assembly, and it is the most interesting thing in this
//! app: everything else here is sockets and string handling.
//!
//! **The send path**, per §9.1: one forward-only ratchet for this member's own
//! leaf, `application` kind. Every message consumes one generation and the
//! consumed secret is destroyed, so the ratchet cannot be rewound.
//!
//! **The receive path**, per §9.2: one `Window` per sender leaf, because
//! messages arrive out of order and a generation may be skipped forever. The
//! window is consume-once (a replay decrypts to nothing the second time) and
//! bounds how far a single message may ratchet forward — the generation is an
//! unauthenticated `uint32` off the wire, so an unbounded jump would let four
//! bytes buy four billion KDF invocations.
//!
//! **Re-keying.** Every Commit changes `encryption_secret`, which invalidates
//! every ratchet and every window: the whole structure is rebuilt at each
//! epoch and the old one wiped. A member that misses a Commit therefore cannot
//! read messages from the new epoch, which is the point.

const std = @import("std");
const mls = @import("mls");

/// The mandatory-to-implement cipher suite (0x0001), as everywhere else here.
pub const S = mls.default_suite;

/// How many generations of one sender's ratchet may be held unconsumed.
///
/// This is the "reasonable amount of time" §9.2 leaves to the application,
/// made concrete. 16 is chosen for a chat app on a reliable stream: the
/// delivery service here relays over TCP and preserves order per sender, so
/// the only reordering to absorb is between a message and the Commit that
/// re-keys everything. A UDP-carried application would want more.
const window_generations = 16;

const Window = mls.secrettree.Window(S, window_generations);

/// One decrypted application message and who sent it.
pub const Opened = struct {
    /// Leaf index of the sender, as authenticated by the sender-data
    /// decryption and then by the signature check — not as claimed in any
    /// plaintext field.
    sender_leaf: u32,
    /// The message text. Owned by the caller.
    text: []u8,
};

pub const Error = error{
    /// The message is for an epoch this member is not in. Not fatal: a
    /// message that raced the Commit that re-keyed the group looks exactly
    /// like this, and the right response is to drop it and say so.
    WrongEpoch,
    /// The sender's leaf is blank or beyond the tree — a message from a
    /// member this member does not have.
    UnknownSender,
    /// The body decrypted but was not an application message. Handshake
    /// messages are sent as `PublicMessage` in this app (see README), so a
    /// `PrivateMessage` carrying a Commit is a protocol violation here.
    NotAnApplicationMessage,
};

/// The §9 state for ONE epoch. Rebuilt from scratch on every Commit.
pub const AppMessages = struct {
    gpa: std.mem.Allocator,

    /// The epoch this state belongs to. Compared against every inbound
    /// message before any key is derived.
    epoch: u64,
    n_leaves: usize,
    my_leaf: u32,

    /// §6.3.2's sender-data secret, copied out of the epoch secrets so the
    /// group object is not borrowed for the lifetime of this struct.
    sender_data_secret: [S.Nh]u8,

    /// §9.1: this member's own application ratchet.
    send: mls.secrettree.Ratchet(S),

    /// §9.2: one receive window per leaf, built lazily — a group of 200 in
    /// which three people talk should not hold 200 windows. `null` means
    /// "nothing received from that leaf in this epoch yet".
    recv: []?Window,

    pub fn init(gpa: std.mem.Allocator, group: *const mls.Group(S)) !AppMessages {
        const n_leaves = group.treeSize();
        const base = try mls.secrettree.ratchetBaseSecret(
            S,
            group.secrets.encryption_secret,
            n_leaves,
            group.my_leaf_index,
            .application,
        );
        const recv = try gpa.alloc(?Window, n_leaves);
        @memset(recv, null);
        return .{
            .gpa = gpa,
            .epoch = group.epoch,
            .n_leaves = n_leaves,
            .my_leaf = group.my_leaf_index,
            .sender_data_secret = group.secrets.sender_data_secret,
            .send = mls.secrettree.Ratchet(S).init(base),
            .recv = recv,
        };
    }

    /// Wipes every ratchet secret this epoch held. Called on re-key as well
    /// as on shutdown, because the old epoch's keys must not outlive it.
    pub fn deinit(self: *AppMessages) void {
        self.send.wipe();
        for (self.recv) |*maybe| if (maybe.*) |*w| w.wipe();
        self.gpa.free(self.recv);
        std.crypto.secureZero(u8, &self.sender_data_secret);
        self.* = undefined;
    }

    /// Rebuild for the group's current epoch if it has moved on. Returns
    /// true when a re-key happened, which is what the caller prints.
    pub fn rekeyIfStale(self: *AppMessages, group: *const mls.Group(S)) !bool {
        if (self.epoch == group.epoch) return false;
        var fresh = try AppMessages.init(self.gpa, group);
        self.deinit();
        self.* = fresh;
        // `fresh` is moved, not dropped: clearing the local guards against a
        // later edit adding a `defer fresh.deinit()` that would wipe the keys
        // this object now owns.
        fresh = undefined;
        return true;
    }

    /// §6.3's encode path for one line of chat. Returns `PrivateMessage`
    /// wire bytes, which is what `protectPrivate` produces — NOT an
    /// `MLSMessage`. The two are not interchangeable and this app's envelope
    /// carries the distinction in its own frame kind rather than re-wrapping.
    pub fn protect(
        self: *AppMessages,
        gpa: std.mem.Allocator,
        io: std.Io,
        group: *const mls.Group(S),
        signature_key_pair: S.Sig.KeyPair,
        text: []const u8,
    ) ![]u8 {
        if (self.epoch != group.epoch) return Error.WrongEpoch;

        const group_context = try group.groupContextAlloc(gpa);
        defer gpa.free(group_context);

        // §6.3.1: freshly random per message, and the module does not
        // generate it — randomness policy is the application's.
        var reuse_guard: [4]u8 = undefined;
        try io.randomSecure(&reuse_guard);

        var key_nonce = try self.send.current();
        defer key_nonce.wipe();
        const generation = self.send.generation;

        const bytes = try mls.protectPrivate(S, gpa, .{
            .signature_key_pair = signature_key_pair,
            .group_context = group_context,
            .content = .{
                .group_id = group.group_id,
                .epoch = group.epoch,
                .sender = .{ .member = self.my_leaf },
                .authenticated_data = &.{},
                .body = .{ .application = text },
            },
            .key_nonce = key_nonce,
            .generation = generation,
            .reuse_guard = reuse_guard,
            .sender_data_secret = self.sender_data_secret,
            // §6.3.1 leaves the amount to the application. A chat line's
            // length is a side channel worth blurring, and 64 bytes is cheap
            // next to the AEAD and signature this message already carries.
            .padding_len = 64,
        });
        errdefer gpa.free(bytes);

        // Only advance once the message actually exists: a failed protect
        // must not burn a generation, or the sender's ratchet runs ahead of
        // what every receiver's window expects.
        try self.send.advance();
        return bytes;
    }

    /// §6.3's decode path, in the order the RFC requires: sender data first
    /// (its key is sampled from the content ciphertext), then the content,
    /// then the signature — verified against the sender's leaf in the
    /// ratchet tree, so "who sent this" is a fact about the group's tree and
    /// not about any field in the message.
    pub fn open(
        self: *AppMessages,
        gpa: std.mem.Allocator,
        group: *const mls.Group(S),
        private_message_bytes: []const u8,
    ) !Opened {
        // `PrivateMessage.decode` takes no allocator and owns nothing: the
        // whole message is slices into `private_message_bytes`, which the
        // caller keeps alive for this call.
        var r = mls.codec.Reader.init(private_message_bytes);
        const pm = try mls.PrivateMessage.decode(&r);

        // Checked before any key is derived: a message from another epoch
        // must not touch this epoch's ratchets at all.
        if (pm.epoch != self.epoch) return Error.WrongEpoch;
        if (pm.content_type != .application) return Error.NotAnApplicationMessage;

        const sd = try mls.decryptSenderData(S, gpa, pm, self.sender_data_secret);
        if (sd.leaf_index >= self.n_leaves) return Error.UnknownSender;

        const sender_key = try leafSignatureKey(group, sd.leaf_index);

        // The window is per sender and created on first sight of that
        // sender, in this epoch only.
        if (self.recv[sd.leaf_index] == null) {
            const base = try mls.secrettree.ratchetBaseSecret(
                S,
                group.secrets.encryption_secret,
                self.n_leaves,
                sd.leaf_index,
                .application,
            );
            self.recv[sd.leaf_index] = Window.init(base);
        }
        var key_nonce = try self.recv[sd.leaf_index].?.get(sd.generation);
        defer key_nonce.wipe();

        const plaintext = try mls.decryptContent(S, gpa, pm, key_nonce, sd.reuse_guard);
        defer gpa.free(plaintext);

        const ac = try mls.parsePrivateContent(gpa, pm, plaintext, sd.leaf_index);
        defer ac.content.body.deinit(gpa);

        const group_context = try group.groupContextAlloc(gpa);
        defer gpa.free(group_context);
        try mls.verifyFramedContent(S, gpa, sender_key, ac, group_context);

        return .{
            .sender_leaf = sd.leaf_index,
            .text = try gpa.dupe(u8, ac.content.body.application),
        };
    }
};

/// The sender's signature key, read out of the group's public ratchet tree.
///
/// ⚠ This reaches into `RatchetTree.nodes` and does the leaf-index-to-node-
/// index doubling itself, because the tree exposes `nodes` and `nLeaves()`
/// and no accessor between them. It is the one place in this app that
/// handles the library's data structure rather than calling a function on
/// it — noted here rather than hidden, since it is exactly the kind of thing
/// a first outside consumer is supposed to surface.
fn leafSignatureKey(group: *const mls.Group(S), leaf_index: u32) !S.Sig.PublicKey {
    const node_index: usize = @as(usize, leaf_index) * 2;
    if (node_index >= group.ratchet_tree.nodes.len) return Error.UnknownSender;
    const node = group.ratchet_tree.nodes[node_index] orelse return Error.UnknownSender;
    const leaf = switch (node) {
        .leaf => |l| l,
        .parent => return Error.UnknownSender,
    };
    if (leaf.signature_key.len != S.Sig.PublicKey.encoded_length) return Error.UnknownSender;
    var raw: [S.Sig.PublicKey.encoded_length]u8 = undefined;
    @memcpy(&raw, leaf.signature_key);
    return S.Sig.PublicKey.fromBytes(raw);
}

/// The display name a member published in its leaf credential, for printing
/// "alice: hello" rather than "leaf 2: hello". A basic credential's identity
/// is opaque bytes by RFC 9420 §5.3 — this app publishes a UTF-8 nickname
/// there and treats it as untrusted display text, never as an identity.
pub fn leafName(group: *const mls.Group(S), leaf_index: u32) ?[]const u8 {
    const node_index: usize = @as(usize, leaf_index) * 2;
    if (node_index >= group.ratchet_tree.nodes.len) return null;
    const node = group.ratchet_tree.nodes[node_index] orelse return null;
    const leaf = switch (node) {
        .leaf => |l| l,
        .parent => return null,
    };
    return switch (leaf.credential) {
        .basic => |identity| identity,
        else => null,
    };
}
