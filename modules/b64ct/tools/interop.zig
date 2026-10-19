// SPDX-License-Identifier: MIT

//! Live differential oracle: b64ct against libsodium's `sodium_bin2base64` /
//! `sodium_base642bin` (the reference of the maturity card), over 300 000
//! cases from a fixed seed — every variant, encode, whole-input decode (with
//! and without an ignore set) and prefix decode (`b64_end`).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-b64ct` runs it and
//! `zig build check-interop` compiles it. Needs `zig` on PATH (it builds
//! `tools/sodium_oracle.c` with `zig cc`) and libsodium 1.0.22's
//! `src/libsodium/sodium/codecs.c` — that one file, compiled against the shim
//! headers in `tools/sodium_shim/` (dir below or `SODIUM_CODECS_SRC`; if it
//! is missing the program prints the fetch recipe and exits 2). Not the
//! distribution's libsodium: 1.0.18 (Ubuntu 24.04's) decodes every octet
//! 0x80–0xff as sextet 63, the signed-`char` defect upstream fixed in
//! a615d0ed ("base64: reject signed chars", 2026-03-29, released in 1.0.22)
//! — this oracle found it (SPEC.md § Compared with). No network. Run from the
//! repository root. Exit 0 = every verdict, every output byte and every
//! prefix length agree.
//!
//! Cases: random octets (0..96) encoded, then optionally sprinkled with
//! characters of the ignore set, then 0..3 mutations (overwrite, delete,
//! insert) from a pool weighted towards the characters that matter — the
//! alphabet, `=`, whitespace, the other alphabet's 62/63, NUL — and for
//! prefix cases a trailer. libsodium only says "error", so a rejected input
//! is compared as a verdict.
//!
//! One known difference, bridged here rather than papered over: libsodium's
//! `strchr(ignore, c)` matches the C string's terminator, so with any
//! non-NULL ignore set a NUL is ignored (and an ignore set cannot contain a
//! NUL of its own). b64ct is given the set plus NUL here so the two agree; on
//! its own it ignores exactly the bytes of its slice. `=` in a padded
//! variant's set is in the cases: b64ct skips it inside the data as
//! libsodium does.

const std = @import("std");
const b64ct = @import("b64ct");

const work_dir = ".zig-cache/interop-b64ct";
const default_codecs_src = ".zig-cache/foreign/libsodium-1.0.22";
const codecs_sha256 = "77e675be30ecd8776e0924596bbf305cbc44f41d8df3238fd65c03aa99091b3e";
pub const codecs_version = "libsodium 1.0.22-RELEASE codecs.c";
const recipe =
    \\interop-b64ct: libsodium 1.0.22 codecs.c not found (or not the pinned one) at {s}
    \\  fetch it (and read it before compiling):
    \\    https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/src/libsodium/sodium/codecs.c
    \\  expected sha256: 77e675be30ecd8776e0924596bbf305cbc44f41d8df3238fd65c03aa99091b3e
    \\  then: SODIUM_CODECS_SRC=<dir with codecs.c> zig build interop-b64ct
    \\
;

/// The pinned codecs.c's path, or null (recipe printed) when it is absent or
/// differs.
pub fn codecsPath(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) !?[]const u8 {
    const dir = env.get("SODIUM_CODECS_SRC") orelse default_codecs_src;
    const path = try arena.print("{s}/codecs.c", .{dir});
    const src = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch {
        std.debug.print(recipe, .{dir});
        return null;
    };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(src, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), codecs_sha256)) {
        std.debug.print(recipe, .{dir});
        return null;
    }
    return path;
}
const n_cases = 300_000;

const ignore_sets = [_]?[]const u8{ null, " \t\r\n", "\n", "\r\n", " ", "-_", "+/", "A", "=", "=\n" };
const pool = "ABCDQUIgoz09+/-_=   \n\n\t\r\x00\x7f\xff.!";

const Variant = struct { C: type, sodium: u8 };

fn Ours(comptime C: type) type {
    return struct {
        fn run(arena: std.mem.Allocator, op: u8, ignore: ?[]const u8, input: []const u8) ![]const u8 {
            var out: [4096]u8 = undefined;
            switch (op) {
                'E' => return arena.print("ok {s} 0", .{hexOrDash(arena, C.encode(&out, input))}),
                'D' => {
                    const r = if (ignore) |ig|
                        C.decodeIgnoring(&out, input, withNul(arena, ig))
                    else
                        C.decode(&out, input);
                    const d = r catch return "err";
                    return arena.print("ok {s} {d}", .{ hexOrDash(arena, d), input.len });
                },
                'P' => {
                    const r = C.decodePrefix(&out, input, if (ignore) |ig| withNul(arena, ig) else "") catch return "err";
                    return arena.print("ok {s} {d}", .{ hexOrDash(arena, r.data), r.consumed });
                },
                else => unreachable,
            }
        }
    };
}

fn withNul(arena: std.mem.Allocator, ig: []const u8) []const u8 {
    return std.mem.concat(arena, u8, &.{ ig, "\x00" }) catch @panic("OOM");
}

fn hexOrDash(arena: std.mem.Allocator, b: []const u8) []const u8 {
    if (b.len == 0) return "-";
    return arena.print("{x}", .{b}) catch @panic("OOM");
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    const codecs = try codecsPath(arena, io, init.environ_map) orelse return 2;
    const exe = try arena.print("{s}/sodium_oracle", .{abs});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O2", "-Imodules/b64ct/tools/sodium_shim", "-DSODIUM_CODECS_VERSION=\"" ++ codecs_version ++ "\"", "modules/b64ct/tools/sodium_oracle.c", codecs, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("interop-b64ct: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const ver = try std.process.run(arena, io, .{ .argv = &.{ exe, "--version" } });

    var prng = std.Random.DefaultPrng.init(0x6236_3463_745f_696f);
    const r = prng.random();
    var cases: std.Io.Writer.Allocating = .init(arena);
    const ours = try arena.alloc([]const u8, n_cases);
    const labels = try arena.alloc([]const u8, n_cases);

    for (0..n_cases) |i| {
        const v = r.uintLessThan(u8, 4);
        const roll = r.uintLessThan(u8, 10);
        const op: u8 = if (roll < 2) 'E' else if (roll < 7) 'D' else 'P';
        var ignore = ignore_sets[r.uintLessThan(usize, ignore_sets.len)];
        var plain: [96]u8 = undefined;
        const pn = r.uintAtMost(usize, plain.len);
        r.bytes(plain[0..pn]);

        var text: std.ArrayList(u8) = .empty;
        if (op == 'E') {
            try text.appendSlice(arena, plain[0..pn]);
            ignore = null;
        } else {
            var enc: [200]u8 = undefined;
            const e = switch (v) {
                0 => b64ct.standard.encode(&enc, plain[0..pn]),
                1 => b64ct.standard_no_pad.encode(&enc, plain[0..pn]),
                2 => b64ct.url_safe.encode(&enc, plain[0..pn]),
                else => b64ct.url_safe_no_pad.encode(&enc, plain[0..pn]),
            };
            try text.appendSlice(arena, e);
            if (ignore) |ig| if (ig.len > 0 and r.boolean()) {
                for (0..r.uintAtMost(usize, 6)) |_| {
                    const at = r.uintAtMost(usize, text.items.len);
                    try text.insert(arena, at, ig[r.uintLessThan(usize, ig.len)]);
                }
            };
            for (0..r.uintAtMost(usize, 3)) |_| {
                const c = pool[r.uintLessThan(usize, pool.len)];
                switch (r.uintLessThan(u8, 3)) {
                    0 => if (text.items.len > 0) {
                        text.items[r.uintLessThan(usize, text.items.len)] = c;
                    },
                    1 => if (text.items.len > 0) {
                        _ = text.orderedRemove(r.uintLessThan(usize, text.items.len));
                    },
                    else => try text.insert(arena, r.uintAtMost(usize, text.items.len), c),
                }
            }
            if (op == 'P') try text.appendSlice(arena, switch (r.uintLessThan(u8, 4)) {
                0 => "-----END X-----\n",
                1 => ",rest",
                2 => "=x",
                else => "",
            });
        }

        const sodium: u8 = switch (v) {
            0 => 1,
            1 => 3,
            2 => 5,
            else => 7,
        };
        const input = text.items;
        try cases.writer.print("{c} {d} {s} {s}\n", .{ op, sodium, if (ignore) |ig| hexOrDash(arena, ig) else "-", hexOrDash(arena, input) });
        ours[i] = switch (v) {
            0 => try Ours(b64ct.standard).run(arena, op, ignore, input),
            1 => try Ours(b64ct.standard_no_pad).run(arena, op, ignore, input),
            2 => try Ours(b64ct.url_safe).run(arena, op, ignore, input),
            else => try Ours(b64ct.url_safe_no_pad).run(arena, op, ignore, input),
        };
        labels[i] = try arena.print("{c} variant={d} ignore={s} input={s}", .{ op, sodium, if (ignore) |ig| hexOrDash(arena, ig) else "NULL", hexOrDash(arena, input) });
    }

    const cases_path = try arena.print("{s}/cases.txt", .{abs});
    const verdicts_path = try arena.print("{s}/verdicts.txt", .{abs});
    try cwd.writeFile(io, .{ .sub_path = cases_path, .data = cases.written() });
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, cases_path, verdicts_path } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("interop-b64ct: libsodium side failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    const verdicts = try cwd.readFileAlloc(io, verdicts_path, arena, .limited(1 << 30));

    var lines = std.mem.splitScalar(u8, verdicts, '\n');
    var mismatches: usize = 0;
    var ok: usize = 0;
    var err: usize = 0;
    for (0..n_cases) |i| {
        const theirs = lines.next() orelse return error.ShortVerdicts;
        if (std.mem.eql(u8, theirs, "err")) err += 1 else ok += 1;
        if (!std.mem.eql(u8, theirs, ours[i])) {
            mismatches += 1;
            if (mismatches <= 10) std.debug.print("MISMATCH {s}\n  libsodium: {s}\n  b64ct:     {s}\n", .{ labels[i], theirs, ours[i] });
        }
    }
    std.debug.print("interop-b64ct: {s}: {d} cases ({d} accepted, {d} rejected), {d} mismatches\n", .{ std.mem.trimEnd(u8, ver.stdout, "\n"), n_cases, ok, err, mismatches });
    return if (mismatches == 0) 0 else 1;
}
