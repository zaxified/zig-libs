// SPDX-License-Identifier: MIT

//! One chat participant: an MLS client with a socket to the Delivery Service.
//!
//! **Two threads, one group object.** The socket reader has to process Commits
//! (they arrive when they arrive), and the keyboard has to send messages, and
//! both touch the same `Group` and the same §9 ratchets. A spin lock over that
//! pair is the whole synchronisation story — `mls.Group` is single-owner by
//! design and says so, so the lock is what makes this a legal owner rather
//! than a second one.
//!
//! **Handshakes are `PublicMessage` here.** `mls.Group` refuses a handshake
//! framed as `PrivateMessage` (`error.PrivateHandshakeNotSupported`) because
//! that path needs the §9 secret tree driven for the handshake ratchet too,
//! and the group object does not drive it. RFC 9420 §6 permits either framing,
//! so this app takes the one the library supports and says so out loud rather
//! than discovering it at runtime. The cost is real and worth naming: the
//! Delivery Service can see the group's membership changes, though not its
//! messages.

const std = @import("std");
const mls = @import("mls");
const lockfree = @import("lockfree");
const wire = @import("wire.zig");
const appmsg = @import("appmsg.zig");

const S = appmsg.S;

pub const Options = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 7711,
    name: []const u8 = "anon",
    group: []const u8 = "ops-room",
    /// Create the group rather than waiting for a Welcome.
    create: bool = false,
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    opts: Options,

    // ── long-term identity ──
    sig: S.Sig.KeyPair,
    init_priv: [S.Kem.Nsk]u8,
    enc_priv: [S.Kem.Nsk]u8,
    /// The `MLSMessage(KeyPackage)` this client publishes. Owned.
    published: []u8,

    // ── transport ──
    stream: std.Io.net.Stream,
    writer: *std.Io.net.Stream.Writer,
    write_lock: lockfree.SpinLock = .{},

    // ── group state, guarded by `state_lock` ──
    state_lock: lockfree.SpinLock = .{},
    group: ?mls.Group(S) = null,
    app: ?appmsg.AppMessages = null,

    /// Set when the reader thread has stopped, so the keyboard loop can exit
    /// instead of typing into a dead socket.
    stopped: bool = false,

    /// §12.1: proposals seen in the CURRENT epoch, kept because a Commit may
    /// name them by reference and both `createCommit` and `processCommit`
    /// then need the original message. Owned copies, cleared whenever the
    /// epoch changes — a proposal from a past epoch is not a proposal.
    pending: std.ArrayList([]u8) = .empty,

    /// Set once this member has been removed from the group, so the keyboard
    /// stops offering to send into a group it is not in.
    removed: bool = false,

    /// Set before this end shuts the socket down on purpose. Without it the
    /// reader thread reports our own `/quit` as "the relay closed the
    /// connection", which is a lie about whose decision it was.
    leaving: bool = false,

    /// Drop every cached proposal. Called on every epoch change: §12.1 scopes
    /// a proposal to the epoch it was made in.
    fn clearPending(self: *Client) void {
        for (self.pending.items) |p| self.gpa.free(p);
        self.pending.clearRetainingCapacity();
    }

    /// The leaf that published this nickname, or null. Names are display text
    /// from a `basic` credential, so a duplicate is possible: the FIRST match
    /// wins and the caller is expected to have shown `/who` first.
    fn leafNamed(self: *Client, name: []const u8) ?u32 {
        const g = if (self.group) |*g| g else return null;
        var leaf: u32 = 0;
        while (leaf < g.treeSize()) : (leaf += 1) {
            const who = appmsg.leafName(g, leaf) orelse continue;
            if (std.mem.eql(u8, who, name)) return leaf;
        }
        return null;
    }

    pub fn sendFrame(self: *Client, frame: wire.Frame) !void {
        self.write_lock.lock();
        defer self.write_lock.unlock();
        try wire.send(self.gpa, &self.writer.interface, frame);
    }

    /// Print with the group's own view of who a leaf is. The credential is
    /// attacker-controlled text from this program's point of view — two
    /// members may publish the same nickname — so the leaf index is printed
    /// alongside it and is the thing that is actually authenticated.
    fn printMessage(self: *Client, leaf: u32, text: []const u8) void {
        const who = if (self.group) |*g| appmsg.leafName(g, leaf) else null;
        std.debug.print("{s}#{d}: {s}\n", .{ who orelse "member", leaf, text });
    }
};

/// Build a fresh identity and the KeyPackage that lets anyone add it.
///
/// Every run generates new keys: this app persists nothing, and a KeyPackage
/// is single-use by RFC 9420 §10 anyway. A client that wanted to keep an
/// identity across runs would persist the signature key pair, republish a
/// fresh KeyPackage each time, and — the hard part, deliberately out of scope
/// here — persist the group state that goes with it.
pub fn init(gpa: std.mem.Allocator, io: std.Io, opts: Options) !Client {
    var seed: [S.Kem.Nsk]u8 = undefined;
    try io.randomSecure(&seed);
    const sig = try S.Sig.KeyPair.generateDeterministic(seed);
    try io.randomSecure(&seed);
    const init_pair = try S.Kem.KeyPair.generateDeterministic(seed);
    try io.randomSecure(&seed);
    const enc_pair = try S.Kem.KeyPair.generateDeterministic(seed);
    std.crypto.secureZero(u8, &seed);

    // The KeyPackage borrows `opts.name` for its credential and the arena
    // below owns the encoded copy; the struct itself is not retained past
    // this function, only its bytes.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const kp = try mls.createKeyPackage(S, arena.allocator(), .{
        .signature_key_pair = sig,
        .init_key = init_pair.public_key,
        .encryption_key = enc_pair.public_key,
        .credential = .{ .basic = opts.name },
        .capabilities = .{
            .versions = &.{1},
            .cipher_suites = &.{1},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{1},
        },
        // The module reads no clock, so the validity window is this
        // application's to choose. A real client publishes a bounded one and
        // republishes before it ends; a demo that expires mid-session would
        // teach nothing but confusion.
        .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
    });
    const msg: mls.MLSMessage = .{ .key_package = kp };
    const published = try msg.encodeAlloc(gpa);
    errdefer gpa.free(published);

    const addr = try std.Io.net.IpAddress.parse(opts.host, opts.port);
    const stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("mls-chat: cannot reach the relay at {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return error.RelayUnreachable;
    };

    return .{
        .gpa = gpa,
        .io = io,
        .opts = opts,
        .sig = sig,
        .init_priv = init_pair.secret_key,
        .enc_priv = enc_pair.secret_key,
        .published = published,
        .stream = stream,
        // Filled in by `run`, which owns the writer's buffer.
        .writer = undefined,
    };
}

pub fn deinit(self: *Client) void {
    self.clearPending();
    self.pending.deinit(self.gpa);
    self.gpa.free(self.published);
    if (self.app) |*a| a.deinit();
    if (self.group) |*g| g.deinit();
    std.crypto.secureZero(u8, &self.init_priv);
    std.crypto.secureZero(u8, &self.enc_priv);
    self.stream.close(self.io);
}

/// Publish, subscribe, then read the keyboard until EOF.
pub fn run(self: *Client) !void {
    const gpa = self.gpa;

    const read_buf = try gpa.alloc(u8, wire.max_frame + 4096);
    defer gpa.free(read_buf);
    const write_buf = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(write_buf);

    var reader = self.stream.reader(self.io, read_buf);
    var writer = self.stream.writer(self.io, write_buf);
    self.writer = &writer;

    try self.sendFrame(.{ .kind = .publish, .name = self.opts.name, .msg = self.published });
    try self.sendFrame(.{ .kind = .join, .group = self.opts.group });

    if (self.opts.create) {
        var g = try mls.Group(S).create(gpa, .{
            .io = self.io,
            .group_id = self.opts.group,
            .key_package_msg = self.published,
            .encryption_priv = self.enc_priv,
        });
        errdefer g.deinit();
        var a = try appmsg.AppMessages.init(gpa, &g);
        errdefer a.deinit();
        self.group = g;
        self.app = a;
        std.debug.print("mls-chat: created '{s}' — epoch {d}, {d} member(s)\n", .{
            self.opts.group,
            g.epoch,
            memberCount(&g),
        });
    } else {
        std.debug.print("mls-chat: waiting for a Welcome into '{s}' — ask a member to /invite {s}\n", .{
            self.opts.group,
            self.opts.name,
        });
    }

    const thread = try std.Thread.spawn(.{}, readerThread, .{ self, &reader });
    defer thread.join();
    // ⚠ Registered AFTER the join, so it runs BEFORE it. The reader thread is
    // parked in a blocking read on this socket and nothing else will ever wake
    // it: without this shutdown, `/quit` and end-of-input both hang the
    // process in `join` until the relay happens to disconnect. Found by
    // running the app, not by reading it — the first single-client session
    // never came back.
    defer {
        self.state_lock.lock();
        self.leaving = true;
        self.state_lock.unlock();
        self.stream.shutdown(self.io, .both) catch {};
    }

    try keyboardLoop(self);
}

/// Everything the socket brings in. Runs on its own thread; every touch of
/// the group is under `state_lock`.
fn readerThread(self: *Client, reader: *std.Io.net.Stream.Reader) void {
    const gpa = self.gpa;
    const frame_buf = gpa.alloc(u8, wire.max_frame) catch return;
    defer gpa.free(frame_buf);

    defer {
        self.state_lock.lock();
        self.stopped = true;
        self.state_lock.unlock();
    }

    while (true) {
        const frame = wire.recv(&reader.interface, frame_buf) catch |err| switch (err) {
            error.EndOfStream, error.ReadFailed => {
                self.state_lock.lock();
                const deliberate = self.leaving;
                self.state_lock.unlock();
                if (!deliberate) std.debug.print("mls-chat: the relay closed the connection\n", .{});
                return;
            },
            else => {
                std.debug.print("mls-chat: bad frame from the relay: {t}\n", .{err});
                return;
            },
        };
        handleInbound(self, frame) catch |err| {
            // One bad message must not end the session: a Commit for an
            // epoch this member already left, or a message that raced a
            // re-key, is ordinary traffic.
            std.debug.print("mls-chat: dropped a {t} frame: {t}\n", .{ frame.kind, err });
        };
    }
}

fn handleInbound(self: *Client, frame: wire.Frame) !void {
    const gpa = self.gpa;
    switch (frame.kind) {
        .note => {},

        // The answer to a `/invite` — the KeyPackage of the person to add.
        // The whole invite completes here rather than handing bytes back to
        // the keyboard thread: one thread doing one thing end to end.
        .key_package => {
            if (frame.msg.len == 0) {
                std.debug.print("mls-chat: nobody has published as '{s}'\n", .{frame.name});
                return;
            }
            try commitAdd(self, frame.name, frame.msg);
        },

        .welcome => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            if (self.group != null) return; // already in; a Welcome for someone else
            var g = mls.Group(S).fromWelcome(gpa, .{
                .welcome_msg = frame.msg,
                .key_package_msg = self.published,
                .init_priv = self.init_priv,
                .encryption_priv = self.enc_priv,
            }) catch |err| switch (err) {
                // The ordinary case: the relay fans one Welcome out to every
                // subscriber and each tries its own slot.
                error.NoMatchingKeyPackage => return,
                else => return err,
            };
            errdefer g.deinit();
            const a = try appmsg.AppMessages.init(gpa, &g);
            self.group = g;
            self.app = a;
            std.debug.print("mls-chat: joined '{s}' — epoch {d}, {d} member(s)\n", .{
                self.opts.group,
                g.epoch,
                memberCount(&g),
            });
        },

        .proposal => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            if (self.removed) return;
            const g = if (self.group) |*g| g else return;
            // Cache first, commit second: every member needs the bytes to
            // resolve the reference in whichever Commit lands, including the
            // members that are not the one committing.
            const copy = try gpa.dupe(u8, frame.msg);
            errdefer gpa.free(copy);
            try self.pending.append(gpa, copy);
            try maybeCommitPending(self, g);
        },

        .handshake => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            if (self.removed) return;
            const g = if (self.group) |*g| g else return; // not a member yet
            g.processCommit(.{
                .commit_msg = frame.msg,
                .proposal_msgs = self.pending.items,
            }) catch |err| switch (err) {
                // The module says this outright, so do not infer it. A member
                // removed by a Commit cannot follow that Commit — it is not in
                // the new epoch's tree and there is nothing to derive. The
                // first version of this code looked for a blanked leaf
                // instead and never fired, because `processCommit` refuses
                // before it mutates anything.
                error.RemovedFromGroup => {
                    self.removed = true;
                    std.debug.print("mls-chat: you were removed from '{s}' — /quit\n", .{self.opts.group});
                    return;
                },
                else => return err,
            };
            self.clearPending();
            const rekeyed = try self.app.?.rekeyIfStale(g);
            std.debug.print("mls-chat: epoch {d}, {d} member(s){s}\n", .{
                g.epoch,
                memberCount(g),
                if (rekeyed) " — application keys re-derived" else "",
            });
        },

        .app => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            // Once removed, this member holds no key for the epochs that
            // follow. Reporting each of those as a dropped frame would be
            // noise about the one thing it already knows.
            if (self.removed) return;
            const g = if (self.group) |*g| g else return;
            const opened = try self.app.?.open(gpa, g, frame.msg);
            defer gpa.free(opened.text);
            self.printMessage(opened.sender_leaf, opened.text);
        },

        // Client → relay kinds coming back at us.
        .publish, .fetch, .join => return error.UnexpectedFrame,
    }
}

/// Add one member: build the Commit, send it to the group, send the Welcome
/// to the newcomer. Both go through the relay, which fans them out to every
/// other subscriber — including, for the Welcome, people it is not for. That
/// is normal: §12.4.3.1 expects a joiner to look for its own slot.
fn commitAdd(self: *Client, name: []const u8, key_package_msg: []const u8) !void {
    const gpa = self.gpa;

    var r = mls.codec.Reader.init(key_package_msg);
    const decoded = try mls.MLSMessage.decode(gpa, &r);
    defer decoded.deinit(gpa);
    const kp = switch (decoded) {
        .key_package => |k| k,
        else => return error.NotAKeyPackage,
    };

    self.state_lock.lock();
    defer self.state_lock.unlock();
    const g = if (self.group) |*g| g else {
        std.debug.print("mls-chat: not in the group yet, so there is nothing to add '{s}' to\n", .{name});
        return;
    };

    const created = try g.createCommit(gpa, .{
        .io = self.io,
        .signature_key_pair = self.sig,
        .proposals = &.{.{ .by_value = .{ .add = kp } }},
    });
    defer created.deinit(gpa);

    // The committer has already advanced by the time this returns, so the
    // §9 state is stale until it is rebuilt — before anything is sent, so a
    // message cannot be protected under the old epoch's ratchet.
    _ = try self.app.?.rekeyIfStale(g);

    try self.sendFrame(.{ .kind = .handshake, .group = self.opts.group, .msg = created.commit });
    const w = created.welcome orelse return error.NoWelcomeForAddedMember;
    try self.sendFrame(.{ .kind = .welcome, .group = self.opts.group, .msg = w });

    std.debug.print("mls-chat: added '{s}' — epoch {d}, {d} member(s)\n", .{ name, g.epoch, memberCount(g) });
}

/// Somebody has to turn a floating proposal into a Commit, and the members
/// cannot ask each other who. The rule is therefore derivable from state every
/// member already agrees on: **the lowest occupied leaf that is not the
/// proposer commits.** Deterministic, needs no round trip, and degrades
/// safely — if two members ever did commit at once, the second Commit loses on
/// `error.WrongEpoch` at every receiver and its author simply retries nothing.
///
/// Caller holds `state_lock`.
fn maybeCommitPending(self: *Client, g: *mls.Group(S)) !void {
    if (self.pending.items.len == 0) return;

    // The member being removed must be excluded from the ballot, or a leaver
    // that happens to sit at the lowest leaf elects itself and nobody commits:
    // it cannot commit its own Remove, and it is the only member that never
    // sees this proposal (the relay does not echo a frame to its sender), so
    // the deadlock would be silent on every side.
    const target = removeTarget(self.gpa, self.pending.items[0]);

    var lowest: ?u32 = null;
    var leaf: u32 = 0;
    while (leaf < g.treeSize()) : (leaf += 1) {
        if (g.ratchet_tree.leafNode(leaf) == null) continue; // blank
        if (target != null and leaf == target.?) continue;
        if (lowest == null) lowest = leaf;
    }
    if (lowest != g.my_leaf_index) return; // not this member's turn

    const created = g.createCommit(self.gpa, .{
        .io = self.io,
        .signature_key_pair = self.sig,
        .proposals = &.{.{ .by_reference = self.pending.items[0] }},
    }) catch |err| {
        std.debug.print("mls-chat: could not commit the pending proposal: {t}\n", .{err});
        return;
    };
    defer created.deinit(self.gpa);

    self.clearPending();
    _ = try self.app.?.rekeyIfStale(g);
    try self.sendFrame(.{ .kind = .handshake, .group = self.opts.group, .msg = created.commit });
    std.debug.print("mls-chat: committed a pending proposal — epoch {d}, {d} member(s)\n", .{
        g.epoch,
        memberCount(g),
    });
}

/// How many members the group actually has.
///
/// ⚠ NOT `treeSize()`, which is the tree's width in leaf slots — §12.4.3.3
/// pads a ratchet tree out to `2^(d+1) - 1` nodes, so three members report
/// four leaves, and every Remove leaves a blank behind on top of that. The
/// first version of this app printed `treeSize()` as "member(s)" and
/// cheerfully announced four members in a group of three.
fn memberCount(g: *const mls.Group(S)) usize {
    var n: usize = 0;
    var leaf: u32 = 0;
    while (leaf < g.treeSize()) : (leaf += 1) {
        if (g.ratchet_tree.leafNode(leaf) != null) n += 1;
    }
    return n;
}

/// Which leaf a Remove proposal names, read WITHOUT verifying anything.
///
/// This decides who commits, not whether the proposal is legitimate:
/// `createCommit` re-authenticates it (§12.2 makes that the committer's job),
/// so a forged or corrupted proposal cannot buy anything here beyond electing
/// the wrong router — which shows up as a Commit that fails, not as one that
/// succeeds wrongly.
fn removeTarget(gpa: std.mem.Allocator, mls_message_bytes: []const u8) ?u32 {
    var r = mls.codec.Reader.init(mls_message_bytes);
    const msg = mls.MLSMessage.decode(gpa, &r) catch return null;
    defer msg.deinit(gpa);
    const pm = switch (msg) {
        .public_message => |p| p,
        else => return null,
    };
    const proposal = switch (pm.content.body) {
        .proposal => |p| p,
        else => return null,
    };
    return switch (proposal) {
        .remove => |leaf| leaf,
        else => null,
    };
}

/// `/remove <name>` — one Commit carrying one Remove, by value.
///
/// §12.4 forbids a committer from removing itself in its own Commit, and the
/// module would refuse it; the app refuses it earlier and points at `/leave`,
/// because "you cannot do that here, do this instead" is more use than an
/// error name.
fn removeMember(self: *Client, name: []const u8) !void {
    self.state_lock.lock();
    defer self.state_lock.unlock();
    const g = if (self.group) |*g| g else {
        std.debug.print("mls-chat: not in the group yet\n", .{});
        return;
    };
    const leaf = self.leafNamed(name) orelse {
        std.debug.print("mls-chat: no member named '{s}' in this group\n", .{name});
        return;
    };
    if (leaf == g.my_leaf_index) {
        std.debug.print("mls-chat: a committer cannot remove itself — use /leave\n", .{});
        return;
    }

    const created = g.createCommit(self.gpa, .{
        .io = self.io,
        .signature_key_pair = self.sig,
        .proposals = &.{.{ .by_value = .{ .remove = leaf } }},
    }) catch |err| {
        std.debug.print("mls-chat: could not remove '{s}': {t}\n", .{ name, err });
        return;
    };
    defer created.deinit(self.gpa);

    self.clearPending();
    _ = try self.app.?.rekeyIfStale(g);
    try self.sendFrame(.{ .kind = .handshake, .group = self.opts.group, .msg = created.commit });
    std.debug.print("mls-chat: removed '{s}' (leaf {d}) — epoch {d}, {d} member(s)\n", .{
        name,
        leaf,
        g.epoch,
        memberCount(g),
    });
}

/// `/leave` — propose this member's own Remove and let somebody else commit it.
///
/// This is the shape RFC 9420 forces: a member cannot commit its own removal,
/// so leaving is a proposal plus a wait. The group does not change until a
/// remaining member commits it, and this client is still in the group — still
/// able to send — until that Commit arrives.
fn proposeLeave(self: *Client) !void {
    self.state_lock.lock();
    defer self.state_lock.unlock();
    const g = if (self.group) |*g| g else {
        std.debug.print("mls-chat: not in the group yet\n", .{});
        return;
    };
    const bytes = g.createProposal(self.gpa, .{
        .signature_key_pair = self.sig,
        .proposal = .{ .remove = g.my_leaf_index },
    }) catch |err| {
        std.debug.print("mls-chat: could not propose leaving: {t}\n", .{err});
        return;
    };
    errdefer self.gpa.free(bytes);
    try self.sendFrame(.{ .kind = .proposal, .group = self.opts.group, .msg = bytes });

    // Cache it here too. The relay does not echo a frame back to its sender,
    // so without this the proposer is the ONE member that cannot resolve the
    // reference in the Commit that covers it — and it learns of its own
    // removal as `ProposalNotFound` instead of `RemovedFromGroup`.
    try self.pending.append(self.gpa, bytes);
    std.debug.print("mls-chat: proposed your own Remove — waiting for a member to commit it\n", .{});
}

const help =
    \\Commands:
    \\  /invite <name>   add the member who published under <name>
    \\  /remove <name>   commit a Remove for that member
    \\  /leave           propose your own Remove; another member commits it
    \\  /who             list the group's leaves
    \\  /quit            disconnect (does NOT remove you from the group)
    \\Anything else is sent to the group as an application message.
    \\
;

fn keyboardLoop(self: *Client) !void {
    const gpa = self.gpa;
    var stdin_buf: [4096]u8 = undefined;
    var stdin = std.Io.File.stdin().reader(self.io, &stdin_buf);

    std.debug.print("{s}", .{help});

    while (true) {
        {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            if (self.stopped) return;
        }

        // ⚠ `takeDelimiter`, NOT `takeDelimiterExclusive`. The exclusive one
        // leaves the delimiter in the stream, so a loop built on it reads the
        // first line and then spins forever returning empty slices — which is
        // exactly what this loop did until it was run.
        const line = (stdin.interface.takeDelimiter('\n') catch |err| switch (err) {
            // A line longer than the buffer is a paste, not an attack; saying
            // so beats ending the session.
            error.StreamTooLong => {
                std.debug.print("mls-chat: that line is too long to send\n", .{});
                continue;
            },
            error.ReadFailed => return,
        }) orelse return;
        const text = std.mem.trim(u8, line, " \t\r\n");
        if (text.len == 0) continue;

        if (std.mem.eql(u8, text, "/quit")) return;
        if (std.mem.eql(u8, text, "/who")) {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            const g = if (self.group) |*g| g else {
                std.debug.print("mls-chat: not in the group yet\n", .{});
                continue;
            };
            var leaf: u32 = 0;
            while (leaf < g.treeSize()) : (leaf += 1) {
                const who = appmsg.leafName(g, leaf) orelse continue;
                std.debug.print("  leaf {d}: {s}{s}\n", .{
                    leaf,
                    who,
                    if (leaf == g.my_leaf_index) " (you)" else "",
                });
            }
            continue;
        }
        if (std.mem.startsWith(u8, text, "/remove ")) {
            const who = std.mem.trim(u8, text["/remove ".len..], " \t");
            try removeMember(self, who);
            continue;
        }
        if (std.mem.eql(u8, text, "/leave")) {
            try proposeLeave(self);
            continue;
        }
        if (std.mem.startsWith(u8, text, "/invite ")) {
            const who = std.mem.trim(u8, text["/invite ".len..], " \t");
            if (who.len == 0) {
                std.debug.print("{s}", .{help});
                continue;
            }
            // Ask the relay for the KeyPackage; the reader thread completes
            // the invite when the answer arrives.
            try self.sendFrame(.{ .kind = .fetch, .name = who });
            continue;
        }
        if (std.mem.startsWith(u8, text, "/")) {
            std.debug.print("{s}", .{help});
            continue;
        }

        const protected = blk: {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            if (self.removed) {
                std.debug.print("mls-chat: you were removed from this group — nothing to send to\n", .{});
                continue;
            }
            const g = if (self.group) |*g| g else {
                std.debug.print("mls-chat: not in the group yet — nothing to send to\n", .{});
                continue;
            };
            break :blk try self.app.?.protect(gpa, self.io, g, self.sig, text);
        };
        defer gpa.free(protected);
        try self.sendFrame(.{ .kind = .app, .group = self.opts.group, .msg = protected });
    }
}
