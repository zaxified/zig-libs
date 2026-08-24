// SPDX-License-Identifier: MIT

//! The Delivery Service, and the point of the whole demo: it holds no key, and
//! everything it forwards is opaque to it.
//!
//! RFC 9420 §2 leaves the Delivery Service outside the protocol and gives it
//! exactly two jobs: hand out the KeyPackages members publish, and get
//! handshake and application messages to the group. This is those two jobs and
//! nothing else. It never calls into `mls` — the dependency is not even
//! declared in this file — because a delivery service that had to parse MLS
//! would be a delivery service that could be asked to lie about what it parsed.
//!
//! **What it therefore CAN do**, and no honest demo should imply otherwise: it
//! sees who publishes under which name, who subscribes to which group id, the
//! size and timing of every message, and it can drop or reorder anything. MLS
//! protects the content and the membership agreement, not the metadata.
//!
//! **Concurrency.** One thread per connection, a spin lock over the roster.
//! Fan-out happens on the sending peer's thread: it takes the roster lock,
//! then each recipient's write lock, in that order and only that order, so
//! there is no cycle to deadlock on. A recipient whose socket has stopped
//! draining therefore blocks the sender until the write completes — the honest
//! bound of a demo, stated rather than papered over with a queue that would
//! then need its own overflow policy.

const std = @import("std");
const lockfree = @import("lockfree");
const wire = @import("wire.zig");

/// One published KeyPackage, kept until the process exits. A real delivery
/// service expires these — RFC 9420 §10 gives a KeyPackage a lifetime and
/// requires last-resort packages to be replaced after use.
const Published = struct {
    name: []u8,
    key_package: []u8,
};

/// One connected client.
const Conn = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    /// Held while writing, by whichever thread is fanning out to this peer.
    write_lock: lockfree.SpinLock = .{},
    writer: *std.Io.net.Stream.Writer,
    /// Empty until the client sends a `join`. Owned.
    group: []u8 = &.{},
    /// Display name from `publish`, for the relay's own log only. Owned.
    name: []u8 = &.{},
    /// Set by the connection thread when it is about to leave; a fan-out
    /// that sees it skips this peer rather than writing into a closing socket.
    closing: bool = false,

    fn deliver(self: *Conn, gpa: std.mem.Allocator, frame: wire.Frame) void {
        self.write_lock.lock();
        defer self.write_lock.unlock();
        if (self.closing) return;
        wire.send(gpa, &self.writer.interface, frame) catch {
            // A peer that cannot be written to is a peer that is going away;
            // its own thread will notice on the next read and deregister it.
            self.closing = true;
        };
    }
};

pub const Relay = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    lock: lockfree.SpinLock = .{},
    packages: std.ArrayList(Published) = .empty,
    conns: std.ArrayList(*Conn) = .empty,

    pub fn deinit(self: *Relay) void {
        for (self.packages.items) |p| {
            self.gpa.free(p.name);
            self.gpa.free(p.key_package);
        }
        self.packages.deinit(self.gpa);
        self.conns.deinit(self.gpa);
    }

    /// Registry write, under the lock. A name published twice replaces the
    /// earlier package: re-running a client is the common case in a demo, and
    /// silently keeping the stale one would fail a later `add` with a stale
    /// init key rather than at the point of the mistake.
    fn publish(self: *Relay, name: []const u8, key_package: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.packages.items) |*p| {
            if (std.mem.eql(u8, p.name, name)) {
                const fresh = try self.gpa.dupe(u8, key_package);
                self.gpa.free(p.key_package);
                p.key_package = fresh;
                return;
            }
        }
        const name_copy = try self.gpa.dupe(u8, name);
        errdefer self.gpa.free(name_copy);
        const kp_copy = try self.gpa.dupe(u8, key_package);
        errdefer self.gpa.free(kp_copy);
        try self.packages.append(self.gpa, .{ .name = name_copy, .key_package = kp_copy });
    }

    /// Returns a copy, so the caller can write it without holding the lock.
    fn fetch(self: *Relay, gpa: std.mem.Allocator, name: []const u8) !?[]u8 {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.packages.items) |p| {
            if (std.mem.eql(u8, p.name, name)) return try gpa.dupe(u8, p.key_package);
        }
        return null;
    }

    /// Copy one frame to every OTHER subscriber of its group.
    fn fanOut(self: *Relay, from: *Conn, frame: wire.Frame) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.conns.items) |c| {
            if (c == from) continue;
            if (c.group.len == 0 or !std.mem.eql(u8, c.group, frame.group)) continue;
            c.deliver(self.gpa, frame);
        }
    }

    fn register(self: *Relay, c: *Conn) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.conns.append(self.gpa, c);
    }

    fn deregister(self: *Relay, c: *Conn) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.conns.items, 0..) |item, i| {
            if (item == c) {
                _ = self.conns.orderedRemove(i);
                return;
            }
        }
    }
};

pub const Options = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 7711,
};

pub fn serve(gpa: std.mem.Allocator, io: std.Io, opts: Options) !void {
    var relay: Relay = .{ .gpa = gpa, .io = io };
    defer relay.deinit();

    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("mls-chat: cannot parse listen address {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return error.BadAddress;
    };
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("mls-chat: cannot listen on {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return error.ListenFailed;
    };
    defer listener.deinit(io);

    std.debug.print("mls-chat relay: listening on {s}:{d} — holds no key, decodes nothing\n", .{ opts.host, opts.port });

    while (true) {
        const stream = listener.accept(io) catch |err| {
            std.debug.print("mls-chat relay: accept failed: {t}\n", .{err});
            continue;
        };
        const thread = std.Thread.spawn(.{}, connectionThread, .{ &relay, stream }) catch |err| {
            std.debug.print("mls-chat relay: cannot spawn a thread for a peer: {t}\n", .{err});
            var s = stream;
            s.close(io);
            continue;
        };
        // Detached: the relay runs until it is killed, and a connection's
        // resources are owned entirely by its own thread.
        thread.detach();
    }
}

fn connectionThread(relay: *Relay, stream_in: std.Io.net.Stream) void {
    const gpa = relay.gpa;
    const io = relay.io;
    var stream = stream_in;

    const read_buf = gpa.alloc(u8, wire.max_frame + 4096) catch return;
    defer gpa.free(read_buf);
    const write_buf = gpa.alloc(u8, 64 * 1024) catch return;
    defer gpa.free(write_buf);
    const frame_buf = gpa.alloc(u8, wire.max_frame) catch return;
    defer gpa.free(frame_buf);

    var reader = stream.reader(io, read_buf);
    var writer = stream.writer(io, write_buf);

    var conn: Conn = .{
        .gpa = gpa,
        .io = io,
        .stream = stream,
        .writer = &writer,
    };
    relay.register(&conn) catch return;
    defer {
        conn.write_lock.lock();
        conn.closing = true;
        conn.write_lock.unlock();
        relay.deregister(&conn);
        gpa.free(conn.group);
        gpa.free(conn.name);
        stream.close(io);
    }

    while (true) {
        const frame = wire.recv(&reader.interface, frame_buf) catch |err| switch (err) {
            error.EndOfStream, error.ReadFailed => return,
            else => {
                std.debug.print("mls-chat relay: dropping a peer over a bad frame: {t}\n", .{err});
                return;
            },
        };
        handleFrame(relay, &conn, frame) catch |err| {
            std.debug.print("mls-chat relay: dropping a peer: {t}\n", .{err});
            return;
        };
    }
}

fn handleFrame(relay: *Relay, conn: *Conn, frame: wire.Frame) !void {
    const gpa = relay.gpa;
    switch (frame.kind) {
        .publish => {
            if (frame.name.len == 0 or frame.msg.len == 0) return error.MalformedFrame;
            try relay.publish(frame.name, frame.msg);
            gpa.free(conn.name);
            conn.name = try gpa.dupe(u8, frame.name);
            std.debug.print("mls-chat relay: {s} published a KeyPackage ({d} bytes)\n", .{ frame.name, frame.msg.len });
            conn.deliver(gpa, .{ .kind = .note, .msg = "published" });
        },
        .fetch => {
            const found = try relay.fetch(gpa, frame.name);
            defer if (found) |f| gpa.free(f);
            conn.deliver(gpa, .{
                .kind = .key_package,
                .name = frame.name,
                .msg = if (found) |f| f else &.{},
            });
        },
        .join => {
            if (frame.group.len == 0) return error.MalformedFrame;
            relay.lock.lock();
            const old = conn.group;
            conn.group = try gpa.dupe(u8, frame.group);
            relay.lock.unlock();
            gpa.free(old);
            std.debug.print("mls-chat relay: {s} subscribed to '{s}'\n", .{
                if (conn.name.len > 0) conn.name else "a peer",
                frame.group,
            });
        },
        // The four that carry MLS bytes take the same path on purpose: the
        // relay's rule for all of them is "copy to the others", and giving
        // each its own branch would invite a future edit to treat one of them
        // as something it may look inside.
        .handshake, .proposal, .welcome, .app => {
            if (frame.group.len == 0) return error.MalformedFrame;
            relay.fanOut(conn, frame);
        },
        // Relay → client kinds. A client sending one is confused, and saying
        // so beats ignoring it.
        .key_package, .note => return error.UnexpectedFrame,
    }
}
