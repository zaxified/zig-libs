// SPDX-License-Identifier: MIT
//
// `uci`: round-trip stress + parse/serialize alphabet asymmetry.
//
// Three independent checks, all deterministic (seeded PRNG, so a failure is
// replayable):
//
//  A. model -> serialize -> parse -> compare   (the invariant the module doc
//     promises). Against the clean module it should be silent; against a
//     mutant whose suite stayed green it should scream — that is what turns
//     "a mutation survived" into "the standing suite has a real hole".
//
//  B. text -> parse -> serialize               (the OTHER direction): is every
//     input the parser ACCEPTS something the serializer can emit?
//
//  C. parse -> serialize on the documented control-byte asymmetry, by hand.
//
// ⚠ Direction B is why this came over instead of being scored spent. The module
// has exactly two fuzz targets — `fuzz: parse never panics on arbitrary bytes`
// and `fuzz: parse(serialize(pkg)) round-trips` — and both walk the other way,
// from a model outward. Nothing in the suite asks whether text the parser
// accepted can be written back out, which is the read-modify-write path a
// config tool actually performs.
//
// Build:
//   zig build-exe -O ReleaseFast --dep uci -Mmain=roundtrip_stress.zig \
//       -Muci=../src/root.zig --cache-dir <scratch>/zc-rt
// Run: ./roundtrip_stress     (prints a summary; exit 0 always)

const std = @import("std");
const uci = @import("uci");

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.os.linux.write(1, s.ptr, s.len);
}

const iterations = 200_000;

/// Alphabet deliberately includes every character with grammatical meaning in
/// UCI text plus the boundary of `isBareSafe`.
const alpha = "abAB01_-'\"\\ \t#\ncdEF.=@[]";

fn randStr(rng: *std.Random.DefaultPrng, buf: []u8, min: usize, max: usize) []const u8 {
    const r = rng.random();
    const n = min + r.uintLessThan(usize, max - min + 1);
    for (buf[0..n]) |*c| c.* = alpha[r.uintLessThan(usize, alpha.len)];
    return buf[0..n];
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const gpa = dbg.allocator();
    var rng = std.Random.DefaultPrng.init(0x4131_5543);

    // ── A: model -> serialize -> parse ───────────────────────────────────
    var a_ran: usize = 0;
    var a_unserializable: usize = 0;
    var a_reparse_failed: usize = 0;
    var a_reparse_invalid_name: usize = 0;
    var a_mismatch: usize = 0;
    var a_first: [4096]u8 = undefined;
    var a_first_len: usize = 0;
    // ⚠ A bare count of failures is not evidence of anything. `serialize`
    // deliberately does not validate the option KEY (root.zig's comment at the
    // `validTypeChars` call claims U14 makes it round-trip safely either way),
    // so WHICH error comes back decides whether that claim holds.
    var a_first_err: [64]u8 = undefined;
    var a_first_err_len: usize = 0;

    var tbuf: [8]u8 = undefined;
    var nbuf: [8]u8 = undefined;
    var kbufs: [3][8]u8 = undefined;
    var vbufs: [3][12]u8 = undefined;
    var vslices: [3][]const u8 = undefined;
    var opts: [3]uci.Option = undefined;
    var secs: [1]uci.Section = undefined;

    for (0..iterations) |_| {
        const r = rng.random();
        const sec_type = randStr(&rng, &tbuf, 1, tbuf.len);
        const has_name = r.boolean();
        const sec_name: ?[]const u8 = if (has_name) randStr(&rng, &nbuf, 1, nbuf.len) else null;
        const n_opts = r.uintLessThan(usize, 3) + 1;
        for (0..n_opts) |oi| {
            const key = randStr(&rng, &kbufs[oi], 1, kbufs[oi].len);
            kbufs[oi][0] = 'A' + @as(u8, @intCast(oi)); // distinct keys
            vslices[oi] = randStr(&rng, &vbufs[oi], 0, vbufs[oi].len);
            opts[oi] = .{ .key = key, .kind = .single, .values = vslices[oi .. oi + 1] };
        }
        secs[0] = .{ .type = sec_type, .name = sec_name, .anonymous = !has_name, .options = opts[0..n_opts] };
        const pkg = uci.Package{ .sections = secs[0..1] };

        a_ran += 1;
        const text = uci.serialize(gpa, &pkg) catch {
            a_unserializable += 1;
            continue;
        };
        defer gpa.free(text);

        var back = uci.parse(gpa, text) catch |e| {
            a_reparse_failed += 1;
            if (e == error.InvalidName) a_reparse_invalid_name += 1;
            if (a_first_err_len == 0) {
                const en = @errorName(e);
                const k = @min(en.len, a_first_err.len);
                @memcpy(a_first_err[0..k], en[0..k]);
                a_first_err_len = k;
            }
            if (a_first_len == 0 and text.len < a_first.len) {
                @memcpy(a_first[0..text.len], text);
                a_first_len = text.len;
            }
            continue;
        };
        defer back.deinit(gpa);
        if (!pkg.eql(&back)) {
            a_mismatch += 1;
            if (a_first_len == 0 and text.len < a_first.len) {
                @memcpy(a_first[0..text.len], text);
                a_first_len = text.len;
            }
        }
    }

    out("A model->serialize->parse : {d} runs, {d} unserializable(ok), " ++
        "{d} REPARSE-FAILED, {d} MISMATCH\n", .{ a_ran, a_unserializable, a_reparse_failed, a_mismatch });
    if (a_first_err_len > 0)
        out("A reparse errors: {d}/{d} InvalidName, first {s}\n", .{ a_reparse_invalid_name, a_reparse_failed, a_first_err[0..a_first_err_len] });
    if (a_first_len > 0) out("A first counterexample text: <<{s}>>\n", .{a_first[0..a_first_len]});

    // ── B: is everything the parser ACCEPTS serializable? ────────────────
    // Random UCI-shaped text; when parse succeeds, serialize must too.
    var b_parsed: usize = 0;
    var b_unserializable: usize = 0;
    var b_first: [512]u8 = undefined;
    var b_first_len: usize = 0;
    var line_buf: [256]u8 = undefined;

    for (0..iterations) |_| {
        const r = rng.random();
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(gpa);
        try text.appendSlice(gpa, "config t\n");
        const n_lines = r.uintLessThan(usize, 3) + 1;
        for (0..n_lines) |li| {
            const val = randStr(&rng, line_buf[0..10], 0, 10);
            var lb: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&lb, "\toption k{d} {s}\n", .{ li, val }) catch continue;
            try text.appendSlice(gpa, line);
        }
        var pkg = uci.parse(gpa, text.items) catch continue;
        defer pkg.deinit(gpa);
        b_parsed += 1;
        const s = uci.serialize(gpa, &pkg) catch {
            b_unserializable += 1;
            if (b_first_len == 0 and text.items.len < b_first.len) {
                @memcpy(b_first[0..text.items.len], text.items);
                b_first_len = text.items.len;
            }
            continue;
        };
        gpa.free(s);
    }
    out("B parse-accepted then serialize: {d} parsed, {d} NOT SERIALIZABLE\n", .{ b_parsed, b_unserializable });
    if (b_first_len > 0) out("B first counterexample text: <<{s}>>\n", .{b_first[0..b_first_len]});

    // ── C: the documented control-byte asymmetry, by hand ────────────────
    // A raw sub-0x20 byte inside a value is accepted by `parse` (and by real
    // uci) but rejected by `serialize` — so read-modify-write of such a file
    // is impossible. One explicit witness per interesting byte.
    var c_asym: usize = 0;
    for ([_]u8{ 0x01, 0x0b, 0x0c, 0x1b, 0x00 }) |b| {
        var buf: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "config t\n\toption v 'a{c}b'\n", .{b}) catch continue;
        var pkg = uci.parse(gpa, text) catch continue;
        defer pkg.deinit(gpa);
        if (uci.serialize(gpa, &pkg)) |s| {
            gpa.free(s);
        } else |_| {
            c_asym += 1;
            out("C byte 0x{x:0>2} in a value: parse OK, serialize -> UnserializableValue\n", .{b});
        }
    }
    out("C control-byte asymmetry witnesses: {d}/5\n", .{c_asym});
}
