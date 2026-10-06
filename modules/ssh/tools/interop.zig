// SPDX-License-Identifier: MIT

//! Our client's RFC 4256 `keyboard-interactive` against **Go
//! `golang.org/x/crypto/ssh`** (BSD-3-Clause, run as a black box through
//! `tools/go_kbdint`): two challenge rounds ("Password: " without echo, then
//! "Token: " with echo, the second round carrying its own instruction), then
//! an `exec` the Go server answers with the user and command it saw. Second
//! case: a wrong second answer must end in `error.AuthenticationFailed`.
//! The hermetic half (our client against our own server over loopback) is in
//! `src/interop_test.zig`; the OpenSSH live tests there cover the server role.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-ssh` runs it (from the
//! repository root), `zig build check-interop` compiles it. It needs `go` and
//! the module cache for x/crypto (fetched by `go run` if absent, pinned by
//! `go.sum`); a missing one is a failure, not a skip.

const std = @import("std");
const ssh = @import("ssh");

const tool = "modules/ssh/tools/go_kbdint";

const Answers = struct {
    token: []const u8,
    rounds: u32 = 0,
    saw_instruction: bool = false,

    fn respond(ctx: *anyopaque, ch: *const ssh.userauth.KbdChallenge, answers: [][]const u8) bool {
        const self: *Answers = @ptrCast(@alignCast(ctx));
        self.rounds += 1;
        if (std.mem.eql(u8, ch.instruction, "round two")) self.saw_instruction = true;
        for (ch.prompts, answers) |p, *a| {
            if (std.mem.eql(u8, p.text, "Password: ") and !p.echo) {
                a.* = "correct horse";
            } else if (std.mem.eql(u8, p.text, "Token: ") and p.echo) {
                a.* = self.token;
            } else return false;
        }
        return true;
    }
};

const accept_any: ssh.transport.HostKeyPolicy = .{
    .verifier = .{
        .verifyFn = struct {
            // A throwaway key the Go server generated a moment ago: nothing to pin.
            fn f(_: *anyopaque, _: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict {
                return .accept;
            }
        }.f,
    },
    .host = "127.0.0.1",
};

const Outcome = struct { rounds: u32, saw_instruction: bool, out: ?[]u8 };

fn runCase(gpa: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, port: u16, token: []const u8) !Outcome {
    var pbuf: [8]u8 = undefined;
    const port_s = try std.fmt.bufPrint(&pbuf, "{d}", .{port});
    var child = std.process.spawn(io, .{
        .argv = &.{ "go", "-C", tool, "run", ".", port_s },
        .stdout = .pipe,
        .stderr = .inherit,
        .environ_map = env,
    }) catch |e| {
        std.debug.print("could not spawn go ({t}) -- the oracle is required, not optional\n", .{e});
        return e;
    };
    defer child.kill(io);
    {
        var lbuf: [64]u8 = undefined;
        var r = child.stdout.?.readerStreaming(io, &lbuf);
        const line = try r.interface.takeDelimiterExclusive('\n');
        if (!std.mem.eql(u8, line, "READY")) return error.OracleNotReady;
    }

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var t = try ssh.transport.connect(&sr.interface, &sw.interface, gpa, accept_any);
    defer t.deinit();
    var scratch: [4096]u8 = undefined;
    try t.requestService("ssh-userauth", &scratch);
    var answers: Answers = .{ .token = token };
    ssh.userauth.authenticateKeyboardInteractive(&t, gpa, "alice", .{ .ctx = &answers, .respondFn = Answers.respond }, .{}) catch |e| switch (e) {
        error.AuthenticationFailed => return .{ .rounds = answers.rounds, .saw_instruction = answers.saw_instruction, .out = null },
        else => return e,
    };
    const res = try ssh.exec(&t, gpa, "whoami", .{});
    gpa.free(res.stderr);
    return .{ .rounds = answers.rounds, .saw_instruction = answers.saw_instruction, .out = res.stdout };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // `spawn` hands the child an empty environment unless given one, and Go
    // needs HOME (module cache, build cache).
    var env = try init.environ.createMap(gpa);
    defer env.deinit();

    var bad: u32 = 0;
    const good = try runCase(gpa, io, &env, 23471, "123456");
    defer if (good.out) |o| gpa.free(o);
    if (good.rounds != 2 or !good.saw_instruction or good.out == null or
        !std.mem.eql(u8, good.out.?, "kbd-ok user=alice cmd=whoami"))
    {
        std.debug.print("FAIL good answers: rounds={d} instruction={} out={?s}\n", .{ good.rounds, good.saw_instruction, good.out });
        bad += 1;
    }
    const wrong = try runCase(gpa, io, &env, 23472, "000000");
    defer if (wrong.out) |o| gpa.free(o);
    if (wrong.rounds != 2 or wrong.out != null) {
        std.debug.print("FAIL wrong token: rounds={d} out={?s} (must be refused after 2 rounds)\n", .{ wrong.rounds, wrong.out });
        bad += 1;
    }
    std.debug.print("keyboard-interactive vs Go x/crypto/ssh: {d} of 2 cases disagreed\n", .{bad});
    return if (bad == 0) 0 else 1;
}
