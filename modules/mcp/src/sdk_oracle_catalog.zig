// SPDX-License-Identifier: MIT

//! The catalog the MCP Python SDK oracle runs against: one of each thing the
//! module serves. `tools/sdk_oracle/server.zig` carries a copy (the SDK talks
//! to that program); `sdk_oracle.zig` replays the recorded transcript against
//! this one, so a copy that drifted fails the replay.

const std = @import("std");

pub fn Catalog(comptime mcp: type) type {
    return struct {
        pub const info: mcp.Info = .{ .name = "oracle-srv", .version = "1.0.0", .instructions = "SDK oracle" };

        fn echo(_: ?*anyopaque, call: *mcp.ToolCall) bool {
            const text = call.strArg("text") orelse return call.fail("missing 'text'");
            call.write(text);
            return false;
        }

        fn broken(_: ?*anyopaque, call: *mcp.ToolCall) bool {
            return call.fail("this tool always fails");
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

        /// Asks for a name on the 2026-07-28 path (MRTR), greets once answered.
        fn greet(_: ?*anyopaque, call: *mcp.ToolCall) bool {
            if (call.input.elicitation("name")) |r| {
                if (r.action != .accept) {
                    call.write("no name given");
                    return false;
                }
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

        fn readme(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
            req.text(req.uri, "text/plain", "read me\n");
            return true;
        }

        fn item(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
            if (!std.mem.startsWith(u8, req.uri, "oracle://items/")) return false;
            req.text(req.uri, "application/json", "{\"item\":true}");
            return true;
        }

        fn review(_: ?*anyopaque, req: *mcp.PromptRequest) bool {
            const lang = req.strArg("lang") orelse "zig";
            req.printMessage(.user, "Review this {s} code.", .{lang});
            req.message(.assistant, "Paste it.");
            return true;
        }

        pub fn register(server: *mcp.Server) !void {
            try server.addTool(.{
                .name = "echo",
                .description = "Echo text back.",
                .input_schema = "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}",
                .handler = echo,
            });
            try server.addTool(.{
                .name = "broken",
                .description = "Always fails.",
                .input_schema = "{\"type\":\"object\"}",
                .handler = broken,
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
            try server.addTool(.{
                .name = "greet",
                .description = "Asks for a name, then greets.",
                .input_schema = "{\"type\":\"object\"}",
                .handler = greet,
            });
            try server.addResource(.{ .uri = "oracle://readme", .name = "readme", .description = "A text resource.", .mime_type = "text/plain", .handler = readme });
            try server.addResourceTemplate(.{ .uri_template = "oracle://items/{id}", .name = "item", .mime_type = "application/json", .handler = item });
            try server.addPrompt(.{
                .name = "review",
                .description = "Ask for a code review.",
                .arguments = &.{.{ .name = "lang", .description = "Language.", .required = false }},
                .handler = review,
            });
        }
    };
}
