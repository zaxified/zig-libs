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

    /// Set before this end shuts the socket down on purpose. Without it the
    /// reader thread reports our own `/quit` as "the relay closed the
    /// connection", which is a lie about whose decision it was.
    leaving: bool = false,

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
            g.treeSize(),
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
                g.treeSize(),
            });
        },

        .handshake => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
            const g = if (self.group) |*g| g else return; // not a member yet
            try g.processCommit(.{ .commit_msg = frame.msg });
            const rekeyed = try self.app.?.rekeyIfStale(g);
            std.debug.print("mls-chat: epoch {d}, {d} member(s){s}\n", .{
                g.epoch,
                g.treeSize(),
                if (rekeyed) " — application keys re-derived" else "",
            });
        },

        .app => {
            self.state_lock.lock();
            defer self.state_lock.unlock();
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

    std.debug.print("mls-chat: added '{s}' — epoch {d}, {d} member(s)\n", .{ name, g.epoch, g.treeSize() });
}

const help =
    \\Commands:
    \\  /invite <name>   add the member who published under <name>
    \\  /who             list the group's leaves
    \\  /quit            leave
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
