// SPDX-License-Identifier: MIT

//! What a remote-command runner does with `ssh`: connect over TCP, complete
//! the transport handshake and publickey authentication, run one command,
//! and read back its stdout/stderr plus the RFC 4254 §6.10 exit status.
//!
//! The target is a local `sshd` (`127.0.0.1:22`) — this module builds
//! Linux-only raw sockets underneath `std.Io.net`, so the example needs a
//! real peer to actually succeed; the point of an *example* is that it
//! type-checks against the published API even though this run may not have
//! one.

const std = @import("std");
const ssh = @import("ssh");

/// A caller decides host-key trust; here we just print the fingerprint
/// material and accept, which is what a first-connect / TOFU client does
/// before it has a known_hosts entry to compare against.
fn acceptAnyHostKey(key_type: []const u8, key_blob: []const u8) bool {
    std.debug.print("host key: {s} ({d} bytes)\n", .{ key_type, key_blob.len });
    return true;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const host = "127.0.0.1";
    const port: u16 = 22;

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch |err| {
        std.debug.print("bad address {s}:{d}: {t}\n", .{ host, port, err });
        return;
    };
    var stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("cannot connect to {s}:{d}: {t}\n", .{ host, port, err });
        return;
    };
    defer stream.close(io);

    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var transport = ssh.transport.connect(&sr.interface, &sw.interface, gpa, acceptAnyHostKey) catch |err| {
        std.debug.print("handshake failed: {t}\n", .{err});
        return;
    };

    // A throwaway client key: a real caller loads one with
    // `ssh.userauth.AuthKey.fromOpenSSH(id_ed25519_text, null)` instead. This
    // one is never in the peer's authorized_keys, so AuthenticationFailed is
    // the expected, nameable outcome against a real sshd.
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(io);
    const key: ssh.userauth.AuthKey = .{ .ed25519 = kp };

    if (ssh.authenticate(&transport, gpa, "demo", key)) |_| {
        var result = try ssh.exec(&transport, gpa, "uname -a", .{});
        defer result.deinit(gpa);
        std.debug.print("stdout: {s}", .{result.stdout});
        std.debug.print("stderr: {s}", .{result.stderr});
        std.debug.print("exit_status: {?d}\n", .{result.exit_status});
    } else |err| switch (err) {
        error.AuthenticationFailed => std.debug.print("authentication failed (expected: throwaway key)\n", .{}),
        else => return err,
    }
}
