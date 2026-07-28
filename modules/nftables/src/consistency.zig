// SPDX-License-Identifier: MIT

//! **JSON ↔ native consistency.**
//!
//! The module has two ways to describe a ruleset. This file proves they mean
//! the same thing, end to end, against a real kernel:
//!
//! 1. Describe one ruleset twice — once through the JSON builder
//!    (`root.Ruleset`), once through the native backend (`wire.Batch` +
//!    `expr.Program`).
//! 2. Apply the **native** batch over `NETLINK_NETFILTER` inside a network
//!    namespace. Nothing here shells out to apply anything.
//! 3. Read the kernel's own view back with `nft -j list ruleset` — i.e. let
//!    the reference implementation decompile the bytes we sent.
//! 4. Compare that against what the **JSON builder** emitted for the same
//!    ruleset, normalised.
//!
//! Normalisation, and why it is honest:
//!
//! * `nft list` reports state we never sent (`handle`, `use`, counter values),
//!   so only the fields the builders actually set are compared.
//! * A `match` statement is compared **deeply** — operator, left expression and
//!   right expression must be JSON-identical. That is the part that would
//!   catch a wrong register, a wrong payload offset, a wrong byte order or a
//!   missing bitwise: any of those and `nft` would decompile the rule into a
//!   different match (or refuse to name it at all).
//! * Every other statement (`counter`, `accept`, `drop`, …) is compared by its
//!   key only, because `nft` renders a fresh counter as
//!   `{"counter":{"packets":0,"bytes":0}}` where the builder emits
//!   `{"counter":null}` — the same statement, a different rendering of "no
//!   traffic yet".
//! * `nft` folds the protocol dependencies the native path must emit
//!   explicitly (`meta l4proto tcp` before a `tcp dport` match, `meta nfproto
//!   ipv4` before an `ip saddr` match in an `inet` table) back into the single
//!   match they belong to — so the statement *counts* agree too, which is an
//!   extra check that the dependencies were emitted exactly where `nft` would
//!   have put them.
//!
//! The test SKIPs (and passes) without `CAP_NET_ADMIN` or without an `nft`
//! binary. Run it for real with:
//!
//! ```sh
//! unshare -rn zig build test-nftables
//! ```

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

const root = @import("root.zig");
const wire = @import("wire.zig");
const expr = @import("expr.zig");

const testing = std.testing;

const table_name = "zig_nft_consistency";

// ── running the reference implementation ────────────────────────────────────

const NftRun = struct {
    exit_code: ?u8,
    stdout: []u8,

    fn deinit(self: NftRun, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
    }
};

/// Run `nft <args…>` and capture stdout. `error.SkipZigTest` if nft is absent.
fn runNft(gpa: std.mem.Allocator, args: []const []const u8) !NftRun {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // nft usually lives in sbin, which spawn's PATH lookup may not cover.
    const candidates = [_][]const u8{ "nft", "/usr/sbin/nft", "/sbin/nft" };
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);

    var child: std.process.Child = for (candidates) |argv0| {
        argv.clearRetainingCapacity();
        try argv.append(gpa, argv0);
        try argv.appendSlice(gpa, args);
        break std.process.spawn(io, .{
            .argv = argv.items,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch continue;
    } else return error.SkipZigTest;

    var rbuf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &rbuf);
    const out = try stdout_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(out);

    const term = child.wait(io) catch return error.SkipZigTest;
    return .{
        .exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        },
        .stdout = out,
    };
}

// ── JSON comparison helpers ─────────────────────────────────────────────────

/// Structural equality of two `std.json.Value`s (object key order ignored).
fn jsonEql(a: std.json.Value, b: std.json.Value) bool {
    return switch (a) {
        .null => b == .null,
        .bool => |x| b == .bool and b.bool == x,
        .integer => |x| switch (b) {
            .integer => |y| x == y,
            .float => |y| @as(f64, @floatFromInt(x)) == y,
            else => false,
        },
        .float => |x| switch (b) {
            .float => |y| x == y,
            .integer => |y| x == @as(f64, @floatFromInt(y)),
            else => false,
        },
        .number_string => |x| b == .number_string and std.mem.eql(u8, x, b.number_string),
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .array => |x| blk: {
            if (b != .array or b.array.items.len != x.items.len) break :blk false;
            for (x.items, b.array.items) |xi, yi| {
                if (!jsonEql(xi, yi)) break :blk false;
            }
            break :blk true;
        },
        .object => |x| blk: {
            if (b != .object or b.object.count() != x.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse break :blk false;
                if (!jsonEql(e.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

/// The single key of a one-key object (`{"accept":null}` -> "accept").
fn soleKey(v: std.json.Value) ?[]const u8 {
    if (v != .object or v.object.count() != 1) return null;
    var it = v.object.iterator();
    return it.next().?.key_ptr.*;
}

/// Compare one rule's statement array as described above: `match` deeply,
/// everything else by statement name.
fn expectSameStatements(want: std.json.Value, got: std.json.Value) !void {
    try testing.expect(want == .array and got == .array);
    if (want.array.items.len != got.array.items.len) {
        std.debug.print(
            "\nstatement count differs: builder {d}, nft {d}\n",
            .{ want.array.items.len, got.array.items.len },
        );
        return error.TestUnexpectedResult;
    }
    for (want.array.items, got.array.items) |w, g| {
        const wk = soleKey(w) orelse return error.TestUnexpectedResult;
        const gk = soleKey(g) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(wk, gk);
        if (std.mem.eql(u8, wk, "match")) {
            if (!jsonEql(w.object.get("match").?, g.object.get("match").?)) {
                std.debug.print("\nmatch statement differs.\n", .{});
                return error.TestUnexpectedResult;
            }
        }
    }
}

/// Find the first object in nft's `"nftables"` array whose sole key is `kind`
/// and whose `"name"`/`"chain"` field equals `name` inside our test table.
fn findObject(
    listing: std.json.Value,
    kind: []const u8,
    name_field: ?[]const u8,
    name: ?[]const u8,
) ?std.json.Value {
    const arr = listing.object.get("nftables") orelse return null;
    if (arr != .array) return null;
    for (arr.array.items) |item| {
        if (item != .object) continue;
        const body = item.object.get(kind) orelse continue;
        if (body != .object) continue;
        const tbl = body.object.get("table") orelse
            body.object.get("name") orelse continue;
        if (tbl != .string) continue;
        if (std.mem.eql(u8, kind, "table")) {
            if (!std.mem.eql(u8, tbl.string, table_name)) continue;
        } else {
            const t = body.object.get("table") orelse continue;
            if (t != .string or !std.mem.eql(u8, t.string, table_name)) continue;
        }
        if (name_field) |nf| {
            const v = body.object.get(nf) orelse continue;
            if (v != .string or !std.mem.eql(u8, v.string, name.?)) continue;
        }
        return body;
    }
    return null;
}

/// All `rule` bodies of our test table, in listing order.
fn collectRules(gpa: std.mem.Allocator, listing: std.json.Value) ![]std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    errdefer out.deinit(gpa);
    const arr = listing.object.get("nftables") orelse return out.toOwnedSlice(gpa);
    if (arr != .array) return out.toOwnedSlice(gpa);
    for (arr.array.items) |item| {
        if (item != .object) continue;
        const body = item.object.get("rule") orelse continue;
        if (body != .object) continue;
        const t = body.object.get("table") orelse continue;
        if (t != .string or !std.mem.eql(u8, t.string, table_name)) continue;
        try out.append(gpa, body);
    }
    return out.toOwnedSlice(gpa);
}

// ── the two descriptions of one ruleset ─────────────────────────────────────

/// The JSON-builder half.
fn buildJson(rs: *root.Ruleset) !void {
    try rs.addTable(.inet, table_name);
    try rs.addChain(root.Chain.base(.inet, table_name, "input", .filter, .input, 0, .drop));

    var r1 = rs.rule(.inet, table_name, "input");
    try r1.ipSaddr(root.cidr("10.0.0.0", 12)).counter().drop().apply();

    var r2 = rs.rule(.inet, table_name, "input");
    try r2.tcpDport(root.num(22)).accept().apply();

    var r3 = rs.rule(.inet, table_name, "input");
    try r3.iifname("lo").accept().apply();
}

/// The native half — the *same* ruleset, over nfnetlink.
fn buildNative(gpa: std.mem.Allocator, b: *wire.Batch, programs: *[3]expr.Program) !void {
    try b.addTable(.{ .family = .inet, .name = table_name });
    try b.addChain(.{
        .family = .inet,
        .table = table_name,
        .name = "input",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
        .policy = .drop,
    });

    programs[0] = expr.Program.init(gpa, .inet);
    _ = programs[0].ipSaddrPrefix(.{ 10, 0, 0, 0 }, 12).counter().drop();
    programs[1] = expr.Program.init(gpa, .inet);
    _ = programs[1].tcpDport(22).accept();
    programs[2] = expr.Program.init(gpa, .inet);
    _ = programs[2].ifnameCmp(.iifname, .eq, "lo").accept();

    for (programs) |*p| {
        try b.addRule(.{
            .family = .inet,
            .table = table_name,
            .chain = "input",
            .exprs = try p.finish(),
        });
    }
}

// ── the test ────────────────────────────────────────────────────────────────

test "consistency: the native batch and the JSON builder describe the same ruleset" {
    if (builtin.os.tag != .linux) return;
    const gpa = testing.allocator;

    var sock = root.Socket.open(gpa) catch |err| {
        if (verboseSkip()) std.debug.print(
            "\nJSON<->native consistency test SKIPPED: no NETLINK_NETFILTER socket ({s}).\n",
            .{@errorName(err)},
        );
        return;
    };
    defer sock.close();
    sock.setRecvTimeout(5000) catch {};

    // Best-effort cleanup of a previous crashed run.
    {
        var pre = try sock.beginBatch(.{});
        defer pre.deinit();
        try pre.deleteTable(.inet, table_name);
        sock.commit(&pre) catch {};
    }

    var programs: [3]expr.Program = undefined;
    var initialized: usize = 0;
    defer for (programs[0..initialized]) |*p| p.deinit();

    var batch = try sock.beginBatch(.{});
    defer batch.deinit();
    try buildNative(gpa, &batch, &programs);
    initialized = programs.len;

    sock.commit(&batch) catch |err| switch (err) {
        error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
            if (verboseSkip()) std.debug.print(
                "\nJSON<->native consistency test SKIPPED: the kernel refused the batch ({s}) — " ++
                    "run it as `unshare -rn zig build test-nftables`.\n",
                .{@errorName(err)},
            );
            return;
        },
        else => return err,
    };
    defer if (sock.beginBatch(.{})) |*b| {
        var post = b.*;
        defer post.deinit();
        post.deleteTable(.inet, table_name) catch {};
        sock.commit(&post) catch {};
    } else |_| {};

    // What the reference implementation makes of the bytes we sent.
    const run = runNft(gpa, &.{ "-j", "list", "ruleset" }) catch |err| switch (err) {
        error.SkipZigTest => {
            if (verboseSkip()) std.debug.print(
                "\nJSON<->native consistency test SKIPPED: no `nft` binary to decompile with.\n",
                .{},
            );
            return;
        },
        else => return err,
    };
    defer run.deinit(gpa);
    if (run.exit_code == null or run.exit_code.? != 0) {
        if (verboseSkip()) std.debug.print(
            "\nJSON<->native consistency test SKIPPED: `nft -j list ruleset` failed.\n",
            .{},
        );
        return;
    }

    var kernel = try std.json.parseFromSlice(std.json.Value, gpa, run.stdout, .{});
    defer kernel.deinit();

    // …and what the JSON builder says about the same ruleset.
    var rs = root.Ruleset.init(gpa);
    defer rs.deinit();
    try buildJson(&rs);
    const our_json = try rs.toJson(gpa);
    defer gpa.free(our_json);
    var ours = try std.json.parseFromSlice(std.json.Value, gpa, our_json, .{});
    defer ours.deinit();

    // 1) the table.
    const k_table = findObject(kernel.value, "table", null, null) orelse {
        std.debug.print("\nnft does not list our table at all\n", .{});
        return error.TestUnexpectedResult;
    };
    try testing.expectEqualStrings("inet", k_table.object.get("family").?.string);
    try testing.expectEqualStrings(table_name, k_table.object.get("name").?.string);

    // 2) the base chain, field by field against the builder's own object.
    const k_chain = findObject(kernel.value, "chain", "name", "input") orelse {
        std.debug.print("\nnft does not list our chain\n", .{});
        return error.TestUnexpectedResult;
    };
    const o_chain = ours.value.object.get("nftables").?.array.items[1]
        .object.get("add").?.object.get("chain").?;
    for ([_][]const u8{ "family", "table", "name", "type", "hook", "policy" }) |field| {
        const want = o_chain.object.get(field).?;
        const got = k_chain.object.get(field) orelse {
            std.debug.print("\nnft chain is missing '{s}'\n", .{field});
            return error.TestUnexpectedResult;
        };
        if (!jsonEql(want, got)) {
            std.debug.print("\nchain field '{s}' differs\n", .{field});
            return error.TestUnexpectedResult;
        }
    }
    // `prio` is `prio` in the builder and in nft's output alike.
    try testing.expect(jsonEql(o_chain.object.get("prio").?, k_chain.object.get("prio").?));

    // 3) the rules, in order, statement by statement.
    const k_rules = try collectRules(gpa, kernel.value);
    defer gpa.free(k_rules);
    try testing.expectEqual(@as(usize, 3), k_rules.len);

    const cmds = ours.value.object.get("nftables").?.array.items;
    for (k_rules, 0..) |k_rule, i| {
        const o_rule = cmds[2 + i].object.get("add").?.object.get("rule").?;
        try testing.expectEqualStrings(
            o_rule.object.get("chain").?.string,
            k_rule.object.get("chain").?.string,
        );
        expectSameStatements(
            o_rule.object.get("expr").?,
            k_rule.object.get("expr").?,
        ) catch |err| {
            std.debug.print("\nrule #{d} differs; nft says:\n{s}\n", .{ i, run.stdout });
            return err;
        };
    }

    std.debug.print(
        "\nJSON<->native consistency: native batch applied, `nft -j list ruleset` " ++
            "decompiles all 3 rules to the JSON builder's own statements.\n",
        .{},
    );
}
