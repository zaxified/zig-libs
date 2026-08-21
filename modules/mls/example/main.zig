// SPDX-License-Identifier: MIT

//! What a group-messaging consumer does with `mls`: publish a KeyPackage for
//! each client, start a group, add members with Commits, land the new member
//! in the same epoch through the Welcome, and derive an application key from
//! the group secret.
//!
//! Every client runs in this process, which is what the module's shape asks
//! for: RFC 9420 deliberately specifies no transport, so `mls` owns no socket
//! and every message here is a `[]u8` a real application would hand to its
//! Delivery Service. Nothing below would change shape if the bytes went over
//! a network in between.
//!
//! The value the members compare at the end is the `epoch_authenticator`. It
//! is derived, not transported: it depends on the tree hash, the whole
//! transcript and the previous epoch's `init_secret`, so two members agreeing
//! on it means they agree on all of that.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const mls = @import("mls");

/// RFC 9420's mandatory-to-implement suite (0x0001) — the one every
/// implementation must speak, so it is what an interoperating client picks.
const S = mls.default_suite;

/// One client's long-term identity plus the published KeyPackage that lets
/// anyone add it to a group. The private halves never leave the client: the
/// group object needs `init_priv` to open its Welcome and `encryption_priv`
/// to open the ratchet tree.
const Client = struct {
    sig: S.Sig.KeyPair,
    init_priv: [S.Kem.Nsk]u8,
    enc_priv: [S.Kem.Nsk]u8,
    key_package: mls.KeyPackage,
    /// The `MLSMessage(KeyPackage)` a client publishes — the byte form every
    /// entry point below takes, not the struct.
    published: []u8,

    fn create(arena: std.mem.Allocator, io: std.Io, name: []const u8) !Client {
        // Three independent key pairs. §10 keeps `init_key` and
        // `encryption_key` distinct on purpose, so joining a group and
        // decrypting inside it never share a key.
        var seed: [S.Kem.Nsk]u8 = undefined;
        try io.randomSecure(&seed);
        const sig = try S.Sig.KeyPair.generateDeterministic(seed);
        try io.randomSecure(&seed);
        const init_pair = try S.Kem.KeyPair.generateDeterministic(seed);
        try io.randomSecure(&seed);
        const enc_pair = try S.Kem.KeyPair.generateDeterministic(seed);
        seed = @splat(0);

        const kp = try mls.createKeyPackage(S, arena, .{
            .signature_key_pair = sig,
            .init_key = init_pair.public_key,
            .encryption_key = enc_pair.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{
                .versions = &.{1},
                .cipher_suites = &.{1},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{1},
            },
            // The module reads no clock, so the validity window is the
            // application's to choose and the receiver's to check. A real
            // client publishes a bounded one and republishes before it ends.
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });

        const msg: mls.MLSMessage = .{ .key_package = kp };
        return .{
            .sig = sig,
            .init_priv = init_pair.secret_key,
            .enc_priv = enc_pair.secret_key,
            .key_package = kp,
            .published = try msg.encodeAlloc(arena),
        };
    }
};

fn report(name: []const u8, g: *const mls.Group(S)) void {
    const auth = g.epochAuthenticator();
    std.debug.print("{s}: epoch {d}, {d} member(s), authenticator {x}\n", .{
        name,
        g.epoch,
        g.treeSize(),
        auth[0..8],
    });
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    // The one capability the module asks for. Group creation and every
    // Commit draw real secrets — §11's `init_secret`, §7.4's `path_secret[0]`,
    // the fresh leaf key pair and an HPKE ephemeral per ciphertext — and the
    // module has no hidden RNG, so the caller supplies the source.
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // KeyPackages and their key material live as long as the clients do.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try Client.create(aa, io, "alice");
    const bob = try Client.create(aa, io, "bob");
    const carol = try Client.create(aa, io, "carol");

    // ── epoch 0: alice alone ────────────────────────────────────────────
    var alice_group = try mls.Group(S).create(gpa, .{
        .io = io,
        // Uniqueness is scoped to the Delivery Service, so naming the group
        // is the application's job, not the protocol's.
        .group_id = "ops-room",
        .key_package_msg = alice.published,
        .encryption_priv = alice.enc_priv,
    });
    defer alice_group.deinit();
    report("alice", &alice_group);

    // ── epoch 1: alice adds bob ─────────────────────────────────────────
    // One Commit produces three messages: the Commit for existing members,
    // a Welcome for everyone it added, and a GroupInfo the Delivery Service
    // can cache. The committer has already advanced when this returns.
    const add_bob = try alice_group.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = bob.key_package } }},
    });
    defer add_bob.deinit(gpa);

    const welcome_for_bob = add_bob.welcome orelse {
        std.debug.print("commit added nobody, so there is no Welcome\n", .{});
        return;
    };

    var bob_group = mls.Group(S).fromWelcome(gpa, .{
        .welcome_msg = welcome_for_bob,
        .key_package_msg = bob.published,
        .init_priv = bob.init_priv,
        .encryption_priv = bob.enc_priv,
    }) catch |err| switch (err) {
        // The Welcome was not addressed to this client's KeyPackage — an
        // ordinary outcome when a Delivery Service fans one Welcome out to
        // several clients and each tries its own slot.
        error.NoMatchingKeyPackage => {
            std.debug.print("bob: this Welcome is not for us\n", .{});
            return;
        },
        // The committer's tree does not hash to what the GroupInfo it signed
        // says. Joining anyway would put bob in a group nobody else is in.
        error.TreeHashMismatch => {
            std.debug.print("bob: refusing a Welcome whose tree does not match\n", .{});
            return;
        },
        else => return err,
    };
    defer bob_group.deinit();

    report("alice", &alice_group);
    report("bob  ", &bob_group);

    // ── epoch 2: alice adds carol, bob follows the Commit ───────────────
    const add_carol = try alice_group.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = carol.key_package } }},
    });
    defer add_carol.deinit(gpa);

    bob_group.processCommit(.{ .commit_msg = add_carol.commit }) catch |err| switch (err) {
        // A Commit for an epoch this member has already left behind, which
        // is what a redelivered message looks like. Checked before anything
        // is mutated, so the group is still usable.
        error.WrongEpoch => {
            std.debug.print("bob: stale Commit, ignoring\n", .{});
            return;
        },
        // The Commit names proposals by reference that this member never
        // received. It has to collect them and retry, not guess.
        error.ProposalNotFound => {
            std.debug.print("bob: missing a referenced proposal\n", .{});
            return;
        },
        // §12.2: the committed proposal list is not one this member will
        // accept, whatever the signature says.
        error.InvalidProposalList => {
            std.debug.print("bob: rejecting an invalid proposal list\n", .{});
            return;
        },
        // Handshake messages framed as `PrivateMessage` need the §9 secret
        // tree driven per epoch, which this group object does not own.
        error.PrivateHandshakeNotSupported => {
            std.debug.print("bob: encrypted handshake messages are not supported\n", .{});
            return;
        },
        else => return err,
    };

    report("alice", &alice_group);
    report("bob  ", &bob_group);

    // A redelivered Commit is the normal case, not an exception: the epoch
    // check rejects it and leaves the group exactly as it was.
    if (bob_group.processCommit(.{ .commit_msg = add_carol.commit })) |_| {
        std.debug.print("unexpected: a replayed Commit advanced the epoch\n", .{});
    } else |err| switch (err) {
        error.WrongEpoch => std.debug.print("bob: replayed Commit ignored, epoch still {d}\n", .{bob_group.epoch}),
        else => return err,
    }

    // The point of all of it: both members hold the same secret without ever
    // having sent it. §8.5's exporter is how an application draws its own
    // keys from that secret — a file-transfer key, a call key, whatever it
    // needs — without touching the group's own key schedule.
    var alice_key: [32]u8 = undefined;
    var bob_key: [32]u8 = undefined;
    try mls.mlsExporter(S, alice_group.secrets.exporter_secret, "example attachment key", "file-1", &alice_key);
    try mls.mlsExporter(S, bob_group.secrets.exporter_secret, "example attachment key", "file-1", &bob_key);
    std.debug.print("exported keys agree: {}\n", .{std.mem.eql(u8, &alice_key, &bob_key)});
}
