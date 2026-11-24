// SPDX-License-Identifier: MIT

//! The catalog `tools/interop.zig` serves to the official MCP Python SDK over
//! HTTP, and that `sdk_oracle.zig` replays the SDK's requests against. Kept in
//! step with its copy `tools/sdk_oracle/catalog.zig` (a file cannot belong to
//! the published module and to that program at once): the replay requires
//! this one to answer exactly what the live run answered.
//!
//! `Live` is what only the live run has (the transport, the `Listens`
//! registry); the replay passes none and skips the exchanges that use it.

const std = @import("std");
const mcp = @import("mcp");

pub const info: mcp.Info = .{ .name = "oracle-http", .version = "1.0.0", .instructions = "SDK oracle over HTTP" };

/// The live run's hooks for the tools that reach the transport.
pub const Live = struct {
    /// `notifyListChanged(.tools)` through the transport's push sink; the
    /// tool runs under the transport lock, as `notify*` must.
    touch: *const fn (ctx: ?*anyopaque) usize,
    /// `Listens.finishAll`.
    finish: *const fn (ctx: ?*anyopaque) void,
    ctx: ?*anyopaque,
    /// Set when the `slow` tool saw `ToolCall.cancelled()`.
    slow_cancelled: std.atomic.Value(bool) = .init(false),
    slow_running: std.atomic.Value(bool) = .init(false),
};

/// Tools whose answers depend on the live run; the replay skips them.
pub const live_only = [_][]const u8{ "touch", "finish_listens", "slow", "slow_cancelled" };

fn echo(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    call.write(text);
    return false;
}

fn add(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const obj = switch (call.args) {
        .object => |o| o,
        else => return call.fail("arguments must be an object"),
    };
    const a = obj.get("a") orelse return call.fail("missing 'a'");
    const b = obj.get("b") orelse return call.fail("missing 'b'");
    if (a != .integer or b != .integer) return call.fail("'a' and 'b' must be integers");
    call.print("{{\"sum\":{d}}}", .{a.integer + b.integer});
    return false;
}

fn greet(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    if (call.input.elicitation("name")) |r| {
        const name = if (r.content) |c| switch (c) {
            .object => |o| if (o.get("name")) |n| switch (n) {
                .string => |s| s,
                else => "?",
            } else "?",
            else => "?",
        } else "?";
        call.print("hello, {s}", .{name});
        return false;
    }
    call.input.ask("name", .{ .elicitation = .{ .form = .{
        .message = "Your name?",
        .requested_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}",
    } } }) catch |err| switch (err) {
        error.SessionRequest => {
            call.write("session path: no multi round-trip");
            return false;
        },
        else => return call.fail("could not ask"),
    };
    return false;
}

fn work(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.reportProgress(1, 2, "half");
    call.reportProgress(2, 2, "done");
    call.write("worked");
    return false;
}

fn touch(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    const live: *Live = @ptrCast(@alignCast(ctx orelse return call.fail("live run only")));
    call.print("{d}", .{live.touch(live.ctx)});
    return false;
}

fn finishListens(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    const live: *Live = @ptrCast(@alignCast(ctx orelse return call.fail("live run only")));
    live.finish(live.ctx);
    call.write("ok");
    return false;
}

fn slow(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    const live: *Live = @ptrCast(@alignCast(ctx orelse return call.fail("live run only")));
    live.slow_running.store(true, .release);
    defer live.slow_running.store(false, .release);
    var i: u32 = 0;
    while (!call.cancelled() and i < 10_000) : (i += 1) {
        var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    if (call.cancelled()) live.slow_cancelled.store(true, .release);
    call.write("slow done");
    return false;
}

fn slowCancelled(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    const live: *Live = @ptrCast(@alignCast(ctx orelse return call.fail("live run only")));
    // The cancelled call may still be unwinding: wait for it (bounded).
    var i: u32 = 0;
    while (live.slow_running.load(.acquire) and i < 5000) : (i += 1) {
        var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    call.write(if (live.slow_cancelled.load(.acquire)) "yes" else "no");
    return false;
}

fn readme(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
    req.text(req.uri, "text/plain", "read me\n");
    return true;
}

fn review(_: ?*anyopaque, req: *mcp.PromptRequest) bool {
    const lang = req.strArg("lang") orelse "zig";
    req.printMessage(.user, "Review this {s} code.", .{lang});
    req.message(.assistant, "Paste it.");
    return true;
}

pub fn register(server: *mcp.Server, live: ?*Live) !void {
    try server.addTool(.{
        .name = "echo",
        .description = "Echo text back.",
        .input_schema = "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}",
        .handler = echo,
    });
    try server.addTool(.{
        .name = "add",
        .description = "Add two integers.",
        .title = "Adder",
        .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"integer\"},\"b\":{\"type\":\"integer\"}},\"required\":[\"a\",\"b\"]}",
        .output_schema = "{\"type\":\"object\",\"properties\":{\"sum\":{\"type\":\"integer\"}},\"required\":[\"sum\"]}",
        .annotations = .{ .read_only_hint = true },
        .handler = add,
    });
    try server.addTool(.{ .name = "greet", .description = "Asks for a name, then greets.", .input_schema = "{\"type\":\"object\"}", .handler = greet });
    try server.addTool(.{ .name = "work", .description = "Reports progress.", .input_schema = "{\"type\":\"object\"}", .handler = work });
    try server.addTool(.{ .name = "touch", .description = "Announce a tools/list change.", .input_schema = "{\"type\":\"object\"}", .handler = touch, .ctx = live });
    try server.addTool(.{ .name = "finish_listens", .description = "End every held listen.", .input_schema = "{\"type\":\"object\"}", .handler = finishListens, .ctx = live });
    try server.addTool(.{ .name = "slow", .description = "Runs until cancelled.", .input_schema = "{\"type\":\"object\"}", .handler = slow, .ctx = live });
    try server.addTool(.{ .name = "slow_cancelled", .description = "Whether slow was cancelled.", .input_schema = "{\"type\":\"object\"}", .handler = slowCancelled, .ctx = live });
    try server.addResource(.{ .uri = "oracle://readme", .name = "readme", .description = "A text resource.", .mime_type = "text/plain", .handler = readme });
    try server.addPrompt(.{
        .name = "review",
        .description = "Ask for a code review.",
        .arguments = &.{.{ .name = "lang", .description = "Language.", .required = false }},
        .handler = review,
    });
}
