// SPDX-License-Identifier: MIT

//! OFFLINE replay of the openapi-spec-validator oracle (`tools/interop.zig`
//! + `tools/spec_oracle.py`, frozen in `spec_oracle_vectors.zig`). No Python
//! at test time.
//!
//! Per route table: the router takes the same routes, `Generator.build`
//! must produce the very document the validator accepted (or refuse with the
//! same error). Per mutation of such a document -- the shapes a generator
//! bug could produce -- `validateOpenApi31`, the check `build` runs on its
//! own output, must answer as the validator did, or as a named class says.

const std = @import("std");
const testing = std.testing;
const router = @import("router");
const openapi = @import("root.zig");
const vectors = @import("spec_oracle_vectors.zig");

fn noop(_: *router.Ctx) anyerror!void {}

test "spec oracle: every route table builds the document the validator accepted" {
    var bad: usize = 0;
    var refused: usize = 0;
    for (vectors.tables, 0..) |t, i| {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        for (t.routes) |rt| {
            if (rt.doc) |d| try r.addDoc(rt.method, rt.pattern, noop, d) else try r.add(rt.method, rt.pattern, noop);
        }
        const got = openapi.Generator.build(testing.allocator, &r, .{
            .title = t.title,
            .version = t.version,
            .description = t.description,
            .bearer_auth = t.bearer,
        });
        if (t.doc) |want| {
            const doc = got catch |e| {
                bad += 1;
                std.debug.print("table {d}: build failed ({t}), the frozen document was accepted\n", .{ i, e });
                continue;
            };
            defer testing.allocator.free(doc);
            if (!t.valid or !std.mem.eql(u8, doc, want)) {
                bad += 1;
                std.debug.print("table {d}: valid={} ({s}); built\n{s}\nfrozen\n{s}\n", .{ i, t.valid, t.why, doc, want });
            }
        } else {
            refused += 1;
            if (got) |doc| {
                testing.allocator.free(doc);
                bad += 1;
                std.debug.print("table {d}: built a document, frozen refusal {s}\n", .{ i, t.err });
            } else |e| if (!std.mem.eql(u8, @errorName(e), t.err)) {
                bad += 1;
                std.debug.print("table {d}: refused with {t}, frozen {s}\n", .{ i, e, t.err });
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    // Every table builds: the one refusal the oracle used to hold (a literal
    // `{x}` static segment) cannot be registered since router reads `{x}` as
    // a capture (2026-10-07); `validateOpenApi31`'s own template check is
    // held by the mutations below (`drop_path_param`).
    try testing.expectEqual(@as(usize, 0), refused);
}

test "spec oracle: validateOpenApi31 answers what the validator answered on each mutation" {
    var bad: usize = 0;
    var seen = [_]usize{0} ** vectors.classes.len;
    for (vectors.mutations) |m| {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, m.doc, .{});
        defer parsed.deinit();
        const ok = if (openapi.validateOpenApi31(parsed.value)) |_| true else |_| false;
        if (ok != m.want) {
            bad += 1;
            if (bad <= 10) std.debug.print("table {d} {s}: checker ok={}, want {} (validator {}: {s})\n", .{ m.table, m.mutation, ok, m.want, m.valid, m.why });
        }
        if (m.class.len != 0) {
            for (vectors.classes, &seen) |name, *n| {
                if (std.mem.eql(u8, name, m.class)) {
                    n.* += 1;
                    break;
                }
            } else bad += 1;
        }
    }
    for (vectors.classes, seen) |name, n| if (n == 0) {
        bad += 1;
        std.debug.print("class {s}: no case\n", .{name});
    };
    try testing.expectEqual(@as(usize, 0), bad);
}
