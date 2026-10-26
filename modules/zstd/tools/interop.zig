// SPDX-License-Identifier: MIT

//! Live interop against the **reference**, libzstd 1.5.7 itself, built from
//! the pinned checkout (`f8745da6`) and driven in-process by
//! `tools/c_oracle/zoracle.c` over a pipe.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-zstd` builds and runs it;
//! `zig build check-interop` only compiles it. The committed goldens
//! (`src/testdata/*goldens.zig`) are libzstd's answers for a FIXED corpus;
//! this program asks libzstd again, about inputs, parameters, schedules and
//! damaged frames generated fresh from a seed, so a divergence the corpus
//! does not reach still shows. Families:
//!
//!   - `compress`  one-shot `compress` against `ZSTD_compress2`: the same
//!                 level, checksum, advanced parameters (a random subset, by
//!                 libzstd's names) and dictionary (loaded or a prefix) must
//!                 give the same bytes, or both refuse with the same error
//!                 code; then each side decodes the other's frame (libzstd
//!                 one-shot, ours one-shot) back to the input.
//!   - `stream`    `Stream.compressStream2` against `ZSTD_compressStream2`
//!                 on a random call schedule (continue/flush/end steps,
//!                 output buffer size, pledged size): the same bytes.
//!   - `decode`    libzstd's frames of the `compress` family through both
//!                 decoders in zdec.c's three modes (one-shot into
//!                 `decompressBound`, streaming fed whole, streaming one byte
//!                 per call): the same output.
//!   - `damaged`   small frames of both encoders with bits flipped, bytes
//!                 replaced, inserted or cut, the tail truncated or extended
//!                 -- the same verdict in all three modes: the same output,
//!                 or the same `ZSTD_ErrorCode`.
//!   - `train`     `dict_builder.train` against `ZDICT_trainFromBuffer` on
//!                 generated samples: the same dictionary, or the same error;
//!                 then frames compressed with it agree (the `compress`
//!                 family with that dictionary).
//!
//! A divergence is a MISMATCH and fails the run, unless its row is listed in
//! `known` below with the reason (a documented gap of this module); those
//! print as GAP and are counted. A decoder that refuses where libzstd decodes
//! (or the reverse) is never a gap by default: it is the finding this
//! program exists for.
//!
//! Usage, from the repository root:
//!
//!   zig build interop-zstd                       # seed 1, default sizes
//!   zig build interop-zstd -- --seed 7 --scale 4 # another seed, 4× the cases
//!   zig build interop-zstd -- --zstd-src DIR     # another checkout of v1.5.7
//!
//! The checkout (default `.zig-cache/zstd-ref`, the one `tools/README.md`
//! clones) must be at `f8745da6`; its `lib/` is compiled with `zig cc`
//! (`-DZSTD_MULTITHREAD`, so `nbWorkers` is libzstd's own) into
//! `.zig-cache/interop-zstd/`, once per change of `zoracle.c`. It does not
//! skip: no checkout, no run.

const std = @import("std");
const zstd = @import("zstd");

const default_src = ".zig-cache/zstd-ref";
const scratch = ".zig-cache/interop-zstd";
const oracle_c = "modules/zstd/tools/c_oracle/zoracle.c";
const pinned_commit = "f8745da6ff1ad1e7bab384bd1f9d742439278e99";

/// Memory cap on one decoded output, both sides (zoracle.c's, too).
const max_output: u64 = 1 << 30;

// ── the peer ────────────────────────────────────────────────────────────────

const Reply = union(enum) { ok: []u8, err: u32 };

const Peer = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    rbuf: [1 << 16]u8 = undefined,
    wbuf: [1 << 16]u8 = undefined,
    r: std.Io.File.Reader = undefined,
    w: std.Io.File.Writer = undefined,

    fn start(p: *Peer) void {
        p.r = p.child.stdout.?.readerStreaming(p.io, &p.rbuf);
        p.w = p.child.stdin.?.writerStreaming(p.io, &p.wbuf);
    }

    fn stop(p: *Peer) void {
        p.child.stdin.?.close(p.io);
        p.child.stdin = null;
        _ = p.child.wait(p.io) catch {};
    }

    fn u8_(p: *Peer, v: u8) !void {
        try p.w.interface.writeByte(v);
    }
    fn u32_(p: *Peer, v: u32) !void {
        try p.w.interface.writeInt(u32, v, .little);
    }
    fn u64_(p: *Peer, v: u64) !void {
        try p.w.interface.writeInt(u64, v, .little);
    }
    fn blob(p: *Peer, b: []const u8) !void {
        try p.u32_(@intCast(b.len));
        try p.w.interface.writeAll(b);
    }

    fn reply(p: *Peer) !Reply {
        try p.w.interface.flush();
        const st = try p.r.interface.takeByte();
        const n = try p.r.interface.takeInt(u32, .little);
        if (st != 0) return .{ .err = n };
        const out = try p.gpa.alloc(u8, n);
        errdefer p.gpa.free(out);
        try p.r.interface.readSliceAll(out);
        return .{ .ok = out };
    }

    fn compress(p: *Peer, level: i32, checksum: bool, plist: []const u8, dict: DictUse, src: []const u8) !Reply {
        try p.u8_('C');
        try p.u32_(@bitCast(level));
        try p.u8_(@intFromBool(checksum));
        try p.blob(plist);
        try p.u8_(@backingInt(dict.mode));
        try p.blob(dict.bytes);
        try p.blob(src);
        return p.reply();
    }

    fn stream(p: *Peer, level: i32, checksum: bool, plist: []const u8, dict: DictUse, sched: Schedule, src: []const u8) !Reply {
        try p.u8_('S');
        try p.u32_(@bitCast(level));
        try p.u8_(@intFromBool(checksum));
        try p.blob(plist);
        try p.u8_(@backingInt(dict.mode));
        try p.blob(dict.bytes);
        try p.u32_(sched.ocap);
        try p.u64_(sched.pledged orelse std.math.maxInt(u64));
        try p.u32_(@intCast(sched.steps.len));
        for (sched.steps) |s| {
            try p.u8_(@backingInt(s.dir));
            try p.u32_(s.len);
        }
        try p.blob(src);
        return p.reply();
    }

    fn decode(p: *Peer, mode: u8, magicless: bool, dict: DictUse, src: []const u8) !Reply {
        try p.u8_('D');
        try p.u8_(mode);
        try p.u8_(@intFromBool(magicless));
        try p.u8_(@backingInt(dict.mode));
        try p.blob(dict.bytes);
        try p.blob(src);
        return p.reply();
    }

    fn train(p: *Peer, cap: u32, sizes: []const usize, samples: []const u8) !Reply {
        try p.u8_('T');
        try p.u32_(cap);
        try p.u32_(@intCast(sizes.len));
        for (sizes) |s| try p.u32_(@intCast(s));
        try p.blob(samples);
        return p.reply();
    }

    fn version(p: *Peer) !Reply {
        try p.u8_('V');
        return p.reply();
    }
};

/// Builds zoracle against the checkout's `lib/` unless a build of the same
/// `zoracle.c` is already there. Returns the executable's path.
fn buildOracle(gpa: std.mem.Allocator, io: std.Io, src_dir: []const u8) ![]const u8 {
    const head = try std.process.run(gpa, io, .{ .argv = &.{ "git", "-C", src_dir, "rev-parse", "HEAD" } });
    defer gpa.free(head.stdout);
    defer gpa.free(head.stderr);
    if (head.term != .exited or head.term.exited != 0 or !std.mem.startsWith(u8, head.stdout, pinned_commit)) {
        std.debug.print("interop-zstd: {s} is not a libzstd checkout at v1.5.7 ({s}); clone it as tools/README.md says\n", .{ src_dir, pinned_commit });
        return error.NoReference;
    }
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, scratch);
    const c_src = try cwd.readFileAlloc(io, oracle_c, gpa, .limited(1 << 20));
    defer gpa.free(c_src);
    var h: [8]u8 = undefined;
    std.mem.writeInt(u64, &h, std.hash.Wyhash.hash(0, c_src), .little);
    const stamp_hex = std.fmt.bytesToHex(h, .lower);
    const exe = scratch ++ "/zoracle";
    const stamp_path = scratch ++ "/zoracle.stamp";
    if (cwd.readFileAlloc(io, stamp_path, gpa, .limited(64))) |old| {
        defer gpa.free(old);
        if (std.mem.eql(u8, old, &stamp_hex)) if (cwd.access(io, exe, .{})) return exe else |_| {};
    } else |_| {}

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    var owned: std.ArrayList([]u8) = .empty;
    defer {
        for (owned.items) |o| gpa.free(o);
        owned.deinit(gpa);
    }
    const inc = try gpa.print("-I{s}/lib", .{src_dir});
    try owned.append(gpa, inc);
    const inc_common = try gpa.print("-I{s}/lib/common", .{src_dir});
    try owned.append(gpa, inc_common);
    try argv.appendSlice(gpa, &.{ "zig", "cc", "-O2", "-DZSTD_MULTITHREAD", "-pthread", inc, inc_common, oracle_c, "-o", exe });
    for ([_][]const u8{ "common", "compress", "decompress", "dictBuilder" }) |part| {
        const dir_path = try gpa.print("{s}/lib/{s}", .{ src_dir, part });
        defer gpa.free(dir_path);
        var dir = try cwd.openDir(io, dir_path, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .file) continue;
            if (!std.mem.endsWith(u8, e.name, ".c") and !std.mem.endsWith(u8, e.name, ".S")) continue;
            const f = try gpa.print("{s}/{s}", .{ dir_path, e.name });
            try owned.append(gpa, f);
            try argv.append(gpa, f);
        }
    }
    std.debug.print("interop-zstd: building libzstd {s} + zoracle with zig cc ...\n", .{pinned_commit[0..8]});
    const r = try std.process.run(gpa, io, .{ .argv = argv.items });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    if (r.term != .exited or r.term.exited != 0) {
        std.debug.print("interop-zstd: zig cc failed:\n{s}\n", .{r.stderr});
        return error.NoReference;
    }
    try cwd.writeFile(io, .{ .sub_path = stamp_path, .data = &stamp_hex });
    return exe;
}

// ── error codes ─────────────────────────────────────────────────────────────

/// `ZSTD_ErrorCode` of one of this module's errors (named after
/// `ZSTD_error_*`); 255 for an error libzstd has no code for.
fn code(e: anyerror) u32 {
    const table = [_]struct { []const u8, u32 }{
        .{ "Generic", 1 },                          .{ "PrefixUnknown", 10 },
        .{ "VersionUnsupported", 12 },              .{ "FrameParameterUnsupported", 14 },
        .{ "FrameParameterWindowTooLarge", 16 },    .{ "CorruptionDetected", 20 },
        .{ "ChecksumWrong", 22 },                   .{ "LiteralsHeaderWrong", 24 },
        .{ "DictionaryCorrupted", 30 },             .{ "DictionaryWrong", 32 },
        .{ "DictionaryCreationFailed", 34 },        .{ "ParameterUnsupported", 40 },
        .{ "ParameterCombinationUnsupported", 41 }, .{ "ParameterOutOfBound", 42 },
        .{ "TableLogTooLarge", 44 },                .{ "MaxSymbolValueTooLarge", 46 },
        .{ "MaxSymbolValueTooSmall", 48 },          .{ "StabilityConditionNotRespected", 50 },
        .{ "StageWrong", 60 },                      .{ "InitMissing", 62 },
        .{ "OutOfMemory", 64 },                     .{ "WorkSpaceTooSmall", 66 },
        .{ "DstSizeTooSmall", 70 },                 .{ "SrcSizeWrong", 72 },
        .{ "DstBufferNull", 74 },                   .{ "NoForwardProgressDestFull", 80 },
        .{ "NoForwardProgressInputEmpty", 82 },
    };
    const name = @errorName(e);
    for (table) |t| if (std.mem.eql(u8, t[0], name)) return t[1];
    return 255;
}

// ── generated inputs ────────────────────────────────────────────────────────

const words = [_][]const u8{
    "the",      "of",        "and",     "zstd",       "frame", "block",  "window",   "match", "literal", "sequence",
    "offset",   "huffman",   "entropy", "dictionary", "level", "stream", "compress", "a",     "is",      "in",
    "{\"id\":", "\"name\":", "</item>", "<item>",     "0x7f",  "    ",   "\n",       ", ",    ". ",      "1970-01-01",
};

/// One of a few input kinds that reach different encoder paths: noise
/// (raw blocks), runs (RLE), text and records (the match finders), a small
/// alphabet (Huffman edge cases), a long-range repeat (beyond the window:
/// long-distance matching), and a mix of them.
fn genInput(gpa: std.mem.Allocator, rnd: std.Random, size: usize) ![]u8 {
    const out = try gpa.alloc(u8, size);
    errdefer gpa.free(out);
    fillKind(rnd, out, rnd.uintLessThan(u8, 7));
    return out;
}

fn fillKind(rnd: std.Random, out: []u8, kind: u8) void {
    switch (kind) {
        0 => rnd.bytes(out),
        1 => {
            var i: usize = 0;
            while (i < out.len) {
                const n = @min(out.len - i, 1 + rnd.uintLessThan(usize, 4000));
                @memset(out[i..][0..n], rnd.int(u8));
                i += n;
            }
        },
        2 => {
            var i: usize = 0;
            while (i < out.len) {
                const w = words[rnd.uintLessThan(usize, words.len)];
                const n = @min(out.len - i, w.len);
                @memcpy(out[i..][0..n], w[0..n]);
                i += n;
            }
        },
        3 => {
            // records: a template with a few bytes changed per copy
            const rec = 16 + rnd.uintLessThan(usize, 200);
            var tmpl: [216]u8 = undefined;
            rnd.bytes(&tmpl);
            var i: usize = 0;
            while (i < out.len) {
                const n = @min(out.len - i, rec);
                @memcpy(out[i..][0..n], tmpl[0..n]);
                for (0..rnd.uintLessThan(usize, 4)) |_| out[i + rnd.uintLessThan(usize, n)] = rnd.int(u8);
                i += n;
            }
        },
        4 => {
            const k = 2 + rnd.uintLessThan(u8, 14);
            for (out) |*b| b.* = 'a' + @as(u8, @intCast(@min(rnd.uintLessThan(u8, k), rnd.uintLessThan(u8, k))));
        },
        5 => {
            // a chunk, noise, the chunk again: matches as far back as the input
            const chunk = out.len / 3;
            if (chunk == 0) return rnd.bytes(out);
            rnd.bytes(out[0..chunk]);
            fillKind(rnd, out[chunk..], 2);
            if (out.len >= 2 * chunk) @memcpy(out[out.len - chunk ..], out[0..chunk]);
        },
        else => {
            var i: usize = 0;
            while (i < out.len) {
                const n = @min(out.len - i, 1 + rnd.uintLessThan(usize, 20000));
                fillKind(rnd, out[i..][0..n], rnd.uintLessThan(u8, 6));
                i += n;
            }
        },
    }
}

/// Log-uniform in 0..max, with the small sizes (0, 1, a few bytes) common.
fn genSize(rnd: std.Random, max: usize) usize {
    if (rnd.uintLessThan(u8, 10) == 0) return rnd.uintLessThan(usize, 8);
    const bits = rnd.uintLessThan(u6, @intCast(std.math.log2_int(usize, max) + 1));
    return @min(max, rnd.uintLessThan(usize, (@as(usize, 1) << bits) + 1));
}

// ── parameters ──────────────────────────────────────────────────────────────

/// A random subset of libzstd's advanced parameters as a `name=value` list,
/// mostly inside libzstd's bounds, now and then just outside (both sides
/// must then refuse alike).
fn genParams(rnd: std.Random, buf: []u8, workers: bool) []const u8 {
    const P = struct { name: []const u8, lo: u32, hi: u32 };
    const table = [_]P{
        .{ .name = "windowLog", .lo = 10, .hi = 25 },
        .{ .name = "hashLog", .lo = 6, .hi = 24 },
        .{ .name = "chainLog", .lo = 6, .hi = 24 },
        .{ .name = "searchLog", .lo = 1, .hi = 10 },
        .{ .name = "minMatch", .lo = 3, .hi = 7 },
        .{ .name = "targetLength", .lo = 0, .hi = 1000 },
        .{ .name = "strategy", .lo = 1, .hi = 9 },
        .{ .name = "contentSizeFlag", .lo = 0, .hi = 1 },
        .{ .name = "format", .lo = 0, .hi = 1 },
        .{ .name = "literalCompressionMode", .lo = 0, .hi = 2 },
        .{ .name = "useRowMatchFinder", .lo = 0, .hi = 2 },
        .{ .name = "splitAfterSequences", .lo = 0, .hi = 2 },
        .{ .name = "blockSplitterLevel", .lo = 0, .hi = 6 },
        .{ .name = "maxBlockSize", .lo = 1024, .hi = 131072 },
        .{ .name = "enableLongDistanceMatching", .lo = 0, .hi = 2 },
        .{ .name = "ldmHashLog", .lo = 6, .hi = 24 },
        .{ .name = "ldmMinMatch", .lo = 4, .hi = 4096 },
        .{ .name = "ldmBucketSizeLog", .lo = 1, .hi = 8 },
        .{ .name = "ldmHashRateLog", .lo = 0, .hi = 15 },
        .{ .name = "targetCBlockSize", .lo = 1340, .hi = 131072 },
        .{ .name = "dictIDFlag", .lo = 0, .hi = 1 },
        .{ .name = "forceMaxWindow", .lo = 0, .hi = 1 },
        .{ .name = "nbWorkers", .lo = 0, .hi = 3 },
        .{ .name = "jobSize", .lo = 0, .hi = 1 << 21 },
        .{ .name = "overlapLog", .lo = 0, .hi = 9 },
        .{ .name = "rsyncable", .lo = 0, .hi = 1 },
    };
    var n: usize = 0;
    const count = rnd.uintLessThan(usize, 5);
    var used: u32 = 0;
    for (0..count) |_| {
        const i = rnd.uintLessThan(usize, table.len);
        if (used & (@as(u32, 1) << @intCast(i)) != 0) continue;
        const p = table[i];
        if (!workers and (std.mem.eql(u8, p.name, "nbWorkers") or std.mem.eql(u8, p.name, "jobSize") or
            std.mem.eql(u8, p.name, "overlapLog") or std.mem.eql(u8, p.name, "rsyncable"))) continue;
        used |= @as(u32, 1) << @intCast(i);
        var v = p.lo + rnd.uintLessThan(u32, p.hi - p.lo + 1);
        if (rnd.uintLessThan(u8, 40) == 0) v = if (p.lo > 0 and rnd.boolean()) p.lo - 1 else p.hi + 1;
        if (std.mem.eql(u8, p.name, "jobSize") and v > 0 and v < 512 << 10) v = 0;
        const sep: []const u8 = if (n == 0) "" else ",";
        const s = std.fmt.bufPrint(buf[n..], "{s}{s}={d}", .{ sep, p.name, v }) catch break;
        n += s.len;
    }
    return buf[0..n];
}

/// `param_test.applyParam`'s reading of the same list, for the parameters
/// `genParams` writes.
fn applyParams(list: []const u8) !zstd.Advanced {
    var adv: zstd.Advanced = .{};
    const switches = [_]zstd.Switch{ .auto, .enable, .disable };
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |tok| {
        const eq = std.mem.findScalar(u8, tok, '=').?;
        const name = tok[0..eq];
        const v = try std.fmt.parseInt(u32, tok[eq + 1 ..], 10);
        const E = struct {
            fn f(a: []const u8, b: []const u8) bool {
                return std.mem.eql(u8, a, b);
            }
        };
        // a three-way switch past 2 is libzstd's parameter_outOfBound at set time
        const is_switch = E.f(name, "literalCompressionMode") or E.f(name, "useRowMatchFinder") or
            E.f(name, "splitAfterSequences") or E.f(name, "enableLongDistanceMatching");
        if (is_switch and v > 2) return error.ParameterOutOfBound;
        if (E.f(name, "format") and v > 1) return error.ParameterOutOfBound;
        // ZSTD_CCtxParams_setParameter: 0 is "use the default" for these,
        // which `zstd.Advanced` spells null
        const zero_default = E.f(name, "windowLog") or E.f(name, "hashLog") or E.f(name, "chainLog") or
            E.f(name, "searchLog") or E.f(name, "minMatch") or E.f(name, "strategy") or
            E.f(name, "ldmHashLog") or E.f(name, "ldmMinMatch") or E.f(name, "ldmBucketSizeLog") or
            E.f(name, "ldmHashRateLog") or E.f(name, "targetCBlockSize") or E.f(name, "maxBlockSize");
        if (zero_default and v == 0) continue;
        const sw = switches[@min(v, 2)];
        if (E.f(name, "windowLog")) {
            adv.window_log = v;
        } else if (E.f(name, "hashLog")) {
            adv.hash_log = v;
        } else if (E.f(name, "chainLog")) {
            adv.chain_log = v;
        } else if (E.f(name, "searchLog")) {
            adv.search_log = v;
        } else if (E.f(name, "minMatch")) {
            adv.min_match = v;
        } else if (E.f(name, "targetLength")) {
            adv.target_length = v;
        } else if (E.f(name, "strategy")) {
            adv.strategy = std.enums.fromInt(zstd.Strategy, v) orelse return error.ParameterOutOfBound;
        } else if (E.f(name, "contentSizeFlag")) {
            adv.content_size = v != 0;
        } else if (E.f(name, "format")) {
            adv.format = if (v == 1) .magicless else .zstd1;
        } else if (E.f(name, "literalCompressionMode")) {
            adv.literal_compression = sw;
        } else if (E.f(name, "useRowMatchFinder")) {
            adv.row_match_finder = sw;
        } else if (E.f(name, "splitAfterSequences")) {
            adv.split_after_sequences = sw;
        } else if (E.f(name, "blockSplitterLevel")) {
            adv.block_splitter_level = v;
        } else if (E.f(name, "maxBlockSize")) {
            adv.max_block_size = v;
        } else if (E.f(name, "enableLongDistanceMatching")) {
            adv.long_distance_matching = sw;
        } else if (E.f(name, "ldmHashLog")) {
            adv.ldm_hash_log = v;
        } else if (E.f(name, "ldmMinMatch")) {
            adv.ldm_min_match = v;
        } else if (E.f(name, "ldmBucketSizeLog")) {
            adv.ldm_bucket_size_log = v;
        } else if (E.f(name, "ldmHashRateLog")) {
            adv.ldm_hash_rate_log = v;
        } else if (E.f(name, "targetCBlockSize")) {
            adv.target_c_block_size = v;
        } else if (E.f(name, "dictIDFlag")) {
            adv.dict_id_flag = v != 0;
        } else if (E.f(name, "forceMaxWindow")) {
            adv.force_max_window = v != 0;
        } else if (E.f(name, "nbWorkers")) {
            adv.nb_workers = v;
        } else if (E.f(name, "jobSize")) {
            adv.job_size = v;
        } else if (E.f(name, "overlapLog")) {
            adv.overlap_log = v;
        } else if (E.f(name, "rsyncable")) {
            adv.rsyncable = v != 0;
        } else unreachable;
    }
    return adv;
}

const DictMode = enum(u8) { none = 0, load = 1, prefix = 2 };
const DictUse = struct { mode: DictMode = .none, bytes: []const u8 = &.{} };

fn ourDict(d: DictUse) zstd.Dictionary {
    return switch (d.mode) {
        .none => .none,
        .load => .{ .raw = .{ .bytes = d.bytes } },
        .prefix => .{ .prefix = .{ .bytes = d.bytes } },
    };
}

// ── tallies ─────────────────────────────────────────────────────────────────

const Family = enum { compress, stream, decode, damaged, train };
var checks = std.EnumArray(Family, usize).initFill(0);
var failures = std.EnumArray(Family, usize).initFill(0);
var gaps = std.EnumArray(Family, usize).initFill(0);
var max_report: usize = 25;

fn ok(f: Family) void {
    checks.getPtr(f).* += 1;
}

fn bad(f: Family, comptime fmt: []const u8, args: anytype) void {
    checks.getPtr(f).* += 1;
    failures.getPtr(f).* += 1;
    if (failures.get(f) <= max_report) std.debug.print("MISMATCH  {t}: " ++ fmt ++ "\n", .{f} ++ args);
}

fn gap(f: Family, comptime fmt: []const u8, args: anytype) void {
    checks.getPtr(f).* += 1;
    gaps.getPtr(f).* += 1;
    if (gaps.get(f) <= 5) std.debug.print("GAP       {t}: " ++ fmt ++ "\n", .{f} ++ args);
}

/// The divergences this module documents (SPEC.md): each a refusal of ours
/// where libzstd compresses, never a different frame.
fn knownCompressGap(e: anyerror) ?[]const u8 {
    return switch (e) {
        // SPEC Backlog: the dictMatchState variants of some strategies
        error.DictAttachUnsupported => "attached CDict for this strategy not ported (frame.BeginError.DictAttachUnsupported)",
        else => null,
    };
}

// ── our side ────────────────────────────────────────────────────────────────

const Ours = union(enum) { ok: []u8, err: anyerror };

fn oursCompress(gpa: std.mem.Allocator, level: i32, checksum: bool, adv: zstd.Advanced, dict: DictUse, src: []const u8) !Ours {
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    const n = zstd.compress(gpa, dst, src, .{ .level = level, .checksum = checksum, .advanced = adv, .dictionary = ourDict(dict) }) catch |e| {
        gpa.free(dst);
        return .{ .err = e };
    };
    return .{ .ok = gpa.realloc(dst, n) catch dst[0..n] };
}

const Step = struct { dir: zstd.EndDirective, len: u32 };
const Schedule = struct { ocap: u32, pledged: ?u64, steps: []const Step };

fn oursStream(gpa: std.mem.Allocator, level: i32, checksum: bool, adv: zstd.Advanced, dict: DictUse, sched: Schedule, src: []const u8) !Ours {
    var s = zstd.Stream.init(gpa, .{ .level = level, .checksum = checksum, .pledged_size = sched.pledged, .advanced = adv, .dictionary = ourDict(dict) }) catch |e| return .{ .err = e };
    defer s.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const obuf = try gpa.alloc(u8, sched.ocap);
    defer gpa.free(obuf);
    var fed: usize = 0;
    for (sched.steps) |st| {
        var in: zstd.InBuffer = .{ .src = src[fed..][0..st.len] };
        while (true) {
            var o: zstd.OutBuffer = .{ .dst = obuf };
            const remaining = s.compressStream2(&o, &in, st.dir) catch |e| {
                out.deinit(gpa);
                return .{ .err = e };
            };
            try out.appendSlice(gpa, obuf[0..o.pos]);
            if (if (st.dir == .@"continue") in.pos == in.src.len else remaining == 0) break;
        }
        fed += st.len;
    }
    return .{ .ok = try out.toOwnedSlice(gpa) };
}

/// zoracle's 'D' request, on this module's decoders.
fn oursDecode(gpa: std.mem.Allocator, mode: u8, magicless: bool, dict: DictUse, src: []const u8) !Ours {
    const format: zstd.Format = if (magicless) .magicless else .zstd1;
    const dict_bytes: ?[]const u8 = if (dict.mode == .load) dict.bytes else null;
    const prefix: ?[]const u8 = if (dict.mode == .prefix) dict.bytes else null;
    if (mode == 0) {
        std.debug.assert(prefix == null);
        const bound = zstd.decompressBound(src) catch return .{ .err = error.SrcSizeWrong };
        if (bound > max_output) return .{ .err = error.OutOfMemory };
        var d = zstd.Decompressor.init(gpa, .{ .format = format, .dictionary = dict_bytes }) catch |e| return .{ .err = e };
        defer d.deinit();
        const dst = try gpa.alloc(u8, @intCast(bound));
        const n = d.decompress(dst, src) catch |e| {
            gpa.free(dst);
            return .{ .err = e };
        };
        return .{ .ok = gpa.realloc(dst, n) catch dst[0..n] };
    }
    var s = zstd.DecompressStream.init(gpa, .{ .window_log_max = 31, .format = format, .dictionary = dict_bytes, .prefix = prefix }) catch |e| return .{ .err = e };
    defer s.deinit();
    const ochunk: usize = if (mode == 1) 1 << 17 else 997;
    const obuf = try gpa.alloc(u8, ochunk);
    defer gpa.free(obuf);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var size: usize = if (mode == 1) src.len else @min(src.len, 1);
    var in: zstd.InBuffer = .{ .src = src[0..size] };
    var r: usize = 1;
    while (true) {
        var o: zstd.OutBuffer = .{ .dst = obuf };
        r = s.decompressStream(&o, &in) catch |e| {
            out.deinit(gpa);
            return .{ .err = e };
        };
        try out.appendSlice(gpa, obuf[0..o.pos]);
        if (out.items.len > max_output) {
            out.deinit(gpa);
            return .{ .err = error.OutOfMemory };
        }
        if (mode == 2 and in.pos == in.src.len and size < src.len) {
            size += 1;
            in.src = src[0..size];
            continue;
        }
        if (in.pos == in.src.len and o.pos < o.dst.len) break;
    }
    if (r != 0) {
        out.deinit(gpa);
        return .{ .err = error.SrcSizeWrong };
    }
    return .{ .ok = try out.toOwnedSlice(gpa) };
}

fn freeOurs(gpa: std.mem.Allocator, o: Ours) void {
    if (o == .ok) gpa.free(o.ok);
}
fn freeReply(gpa: std.mem.Allocator, r: Reply) void {
    if (r == .ok) gpa.free(r.ok);
}

/// Same output, or the same error code. Returns a short description of the
/// difference, or null.
fn differ(buf: []u8, ours: Ours, theirs: Reply) ?[]const u8 {
    switch (ours) {
        .ok => |o| switch (theirs) {
            .ok => |t| {
                if (std.mem.eql(u8, o, t)) return null;
                const at = std.mem.findDiff(u8, o, t) orelse @min(o.len, t.len);
                return std.fmt.bufPrint(buf, "ours {d} B, libzstd {d} B, first difference at {d}", .{ o.len, t.len, at }) catch "output differs";
            },
            .err => |c| return std.fmt.bufPrint(buf, "ours OK ({d} B), libzstd ERR {d}", .{ o.len, c }) catch "verdict differs",
        },
        .err => |e| switch (theirs) {
            .ok => |t| return std.fmt.bufPrint(buf, "ours {t}, libzstd OK ({d} B)", .{ e, t.len }) catch "verdict differs",
            .err => |c| {
                if (code(e) == c) return null;
                return std.fmt.bufPrint(buf, "ours {t} ({d}), libzstd ERR {d}", .{ e, code(e), c }) catch "error differs";
            },
        },
    }
}

// ── the families ────────────────────────────────────────────────────────────

const Ctx = struct {
    gpa: std.mem.Allocator,
    peer: *Peer,
    seed: u64,
    /// Small frames for `damaged`: (frame, magicless, dictionary).
    small: std.ArrayList(SmallFrame) = .empty,
    dicts: std.ArrayList([]u8) = .empty,
};
const SmallFrame = struct { frame: []u8, magicless: bool, dict: DictUse };

fn levelFor(rnd: std.Random, size: usize) i32 {
    while (true) {
        const l: i32 = switch (rnd.uintLessThan(u8, 10)) {
            0 => -@as(i32, rnd.uintLessThan(u8, 8)) - 1,
            1 => if (rnd.boolean()) -1000 else 0,
            else => 1 + @as(i32, rnd.uintLessThan(u8, 22)),
        };
        // the optimal parsers cost 10-40× a lazy level: keep them to the
        // smaller inputs so a run stays in minutes
        if (l >= 16 and size > 256 << 10) continue;
        return l;
    }
}

fn familyCompress(ctx: *Ctx, n: usize, with_dicts: bool) !void {
    const gpa = ctx.gpa;
    var prng: std.Random.DefaultPrng = .init(ctx.seed ^ 0xC0 ^ @as(u64, @intFromBool(with_dicts)));
    const rnd = prng.random();
    var pbuf: [512]u8 = undefined;
    for (0..n) |i| {
        const size = genSize(rnd, if (rnd.uintLessThan(u8, 20) == 0) 4 << 20 else 512 << 10);
        const src = try genInput(gpa, rnd, size);
        defer gpa.free(src);
        const level = levelFor(rnd, size);
        const checksum = rnd.boolean();
        const plist = if (rnd.uintLessThan(u8, 3) == 0) genParams(rnd, &pbuf, size > 256 << 10) else "";
        var dict: DictUse = .{};
        if (with_dicts and ctx.dicts.items.len > 0) {
            const d = ctx.dicts.items[rnd.uintLessThan(usize, ctx.dicts.items.len)];
            dict = .{ .mode = if (rnd.uintLessThan(u8, 4) == 0) .prefix else .load, .bytes = d };
        }
        const adv = applyParams(plist) catch |e| {
            const theirs = try ctx.peer.compress(level, checksum, plist, dict, src);
            defer freeReply(gpa, theirs);
            var dbuf: [160]u8 = undefined;
            if (differ(&dbuf, .{ .err = e }, theirs)) |why| bad(.compress, "case {d} level {d} [{s}]: {s}", .{ i, level, plist, why }) else ok(.compress);
            continue;
        };
        const theirs = try ctx.peer.compress(level, checksum, plist, dict, src);
        defer freeReply(gpa, theirs);
        const ours = try oursCompress(gpa, level, checksum, adv, dict, src);
        defer freeOurs(gpa, ours);
        if (ours == .err and theirs == .ok) if (knownCompressGap(ours.err)) |why| {
            gap(.compress, "case {d} level {d} {d} B dict {t} [{s}]: {s}", .{ i, level, size, dict.mode, plist, why });
            continue;
        };
        var dbuf: [160]u8 = undefined;
        if (differ(&dbuf, ours, theirs)) |why| {
            bad(.compress, "case {d} seed {d} level {d} checksum {} {d} B dict {t} [{s}]: {s}", .{ i, ctx.seed, level, checksum, size, dict.mode, plist, why });
            continue;
        }
        ok(.compress);
        if (theirs == .err) continue;
        const frame = theirs.ok;
        const magicless = adv.format == .magicless;
        // each decodes the other's frame (the bytes are equal: one decode each)
        try decodeBoth(ctx, i, frame, magicless, dict, src);
        if (frame.len <= 4096 and ctx.small.items.len < 4000) {
            try ctx.small.append(gpa, .{ .frame = try gpa.dupe(u8, frame), .magicless = magicless, .dict = dict });
        }
    }
}

/// The `decode` family on one valid frame: every mode both decoders run must
/// give `want` (or both refuse alike: a frame over the memory cap).
fn decodeBoth(ctx: *Ctx, i: usize, frame: []const u8, magicless: bool, dict: DictUse, want: []const u8) !void {
    const gpa = ctx.gpa;
    for ([_]u8{ 0, 1, 2 }) |mode| {
        if (mode == 0 and (magicless or dict.mode == .prefix)) continue; // zdec mode 0: zstd1 frames, no prefix
        if (mode == 2 and frame.len > 64 << 10) continue; // one byte per call: keep it to small frames
        const theirs = try ctx.peer.decode(mode, magicless, dict, frame);
        defer freeReply(gpa, theirs);
        const ours = try oursDecode(gpa, mode, magicless, dict, frame);
        defer freeOurs(gpa, ours);
        var dbuf: [160]u8 = undefined;
        if (differ(&dbuf, ours, theirs)) |why| {
            bad(.decode, "case {d} mode {d}: {s}", .{ i, mode, why });
        } else if (ours == .ok and !std.mem.eql(u8, ours.ok, want)) {
            bad(.decode, "case {d} mode {d}: both decoders agree but not with the input", .{ i, mode });
        } else ok(.decode);
    }
}

fn familyStream(ctx: *Ctx, n: usize) !void {
    const gpa = ctx.gpa;
    var prng: std.Random.DefaultPrng = .init(ctx.seed ^ 0x5E);
    const rnd = prng.random();
    var pbuf: [512]u8 = undefined;
    var steps: std.ArrayList(Step) = .empty;
    defer steps.deinit(gpa);
    for (0..n) |i| {
        const size = genSize(rnd, 1 << 20);
        const src = try genInput(gpa, rnd, size);
        defer gpa.free(src);
        var level = levelFor(rnd, size);
        if (level > zstd.stream_max_level) level = zstd.stream_max_level;
        const checksum = rnd.boolean();
        const plist = if (rnd.uintLessThan(u8, 4) == 0) genParams(rnd, &pbuf, size > 256 << 10) else "";
        const adv = applyParams(plist) catch continue; // the refusals are `compress`'s
        steps.clearRetainingCapacity();
        // one frame: continue/flush steps over the input, an end at the end
        var left = size;
        while (left > 0 and steps.items.len < 64) {
            const take: u32 = @intCast(@min(left, 1 + genSize(rnd, 300 << 10)));
            try steps.append(gpa, .{ .dir = if (rnd.uintLessThan(u8, 4) == 0) .flush else .@"continue", .len = take });
            left -= take;
        }
        try steps.append(gpa, .{ .dir = .end, .len = @intCast(left) });
        const pledged: ?u64 = if (rnd.uintLessThan(u8, 3) == 0) size else null;
        const ocap: u32 = if (rnd.boolean()) 1 << 20 else 1 + rnd.uintLessThan(u32, 4096);
        const sched: Schedule = .{ .ocap = ocap, .pledged = pledged, .steps = steps.items };
        const theirs = try ctx.peer.stream(level, checksum, plist, .{}, sched, src);
        defer freeReply(gpa, theirs);
        const ours = try oursStream(gpa, level, checksum, adv, .{}, sched, src);
        defer freeOurs(gpa, ours);
        var dbuf: [160]u8 = undefined;
        if (differ(&dbuf, ours, theirs)) |why| {
            bad(.stream, "case {d} seed {d} level {d} {d} B, {d} steps, out {d}, pledged {?d} [{s}]: {s}", .{ i, ctx.seed, level, size, steps.items.len, ocap, pledged, plist, why });
        } else ok(.stream);
    }
}

fn familyDamaged(ctx: *Ctx, n: usize) !void {
    const gpa = ctx.gpa;
    if (ctx.small.items.len == 0) return;
    var prng: std.Random.DefaultPrng = .init(ctx.seed ^ 0xDA);
    const rnd = prng.random();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    for (0..n) |i| {
        const base = ctx.small.items[rnd.uintLessThan(usize, ctx.small.items.len)];
        buf.clearRetainingCapacity();
        try buf.appendSlice(gpa, base.frame);
        const edits = 1 + rnd.uintLessThan(u8, 3);
        var what: [3]u8 = undefined;
        for (0..edits) |k| {
            const kind = rnd.uintLessThan(u8, 7);
            what[k] = "fbitxeh"[kind];
            const len = buf.items.len;
            switch (kind) {
                0 => if (len > 0) { // flip a bit
                    buf.items[rnd.uintLessThan(usize, len)] ^= @as(u8, 1) << rnd.int(u3);
                },
                1 => if (len > 0) { // replace a byte
                    buf.items[rnd.uintLessThan(usize, len)] = rnd.int(u8);
                },
                2 => try buf.insert(gpa, rnd.uintLessThan(usize, len + 1), rnd.int(u8)), // insert
                3 => if (len > 0) { // truncate
                    buf.shrinkRetainingCapacity(rnd.uintLessThan(usize, len));
                },
                4 => for (0..1 + rnd.uintLessThan(usize, 16)) |_| try buf.append(gpa, rnd.int(u8)), // extend
                5 => if (len > 0) { // cut a byte
                    _ = buf.orderedRemove(rnd.uintLessThan(usize, len));
                },
                else => if (len > 5) { // a header byte: frame descriptor, window, sizes
                    buf.items[(if (base.magicless) @as(usize, 0) else 4) + rnd.uintLessThan(usize, @min(len - 4, 6))] ^= @as(u8, 1) << rnd.int(u3);
                },
            }
        }
        for ([_]u8{ 0, 1, 2 }) |mode| {
            if (mode == 0 and (base.magicless or base.dict.mode == .prefix)) continue;
            const theirs = try ctx.peer.decode(mode, base.magicless, base.dict, buf.items);
            defer freeReply(gpa, theirs);
            const ours = try oursDecode(gpa, mode, base.magicless, base.dict, buf.items);
            defer freeOurs(gpa, ours);
            var dbuf: [160]u8 = undefined;
            if (differ(&dbuf, ours, theirs)) |why| {
                if (ours == .err and theirs == .err and base.dict.mode != .none) {
                    // dblock.zig's header: with a dictionary libzstd runs
                    // its prefetching loop (`ddictIsCold`), which checks the
                    // bitstream's end before the last sequences execute;
                    // this port picks that loop by its own rule. Both refuse
                    // -- only which check fires first differs.
                    gap(.damaged, "case {d} mode {d} with a dictionary: {s} (both refuse; libzstd's prefetch-loop choice, dblock.zig)", .{ i, mode, why });
                    continue;
                }
                bad(.damaged, "case {d} seed {d} mode {d} edits {s} on a {d}-byte frame: {s}", .{ i, ctx.seed, mode, what[0..edits], base.frame.len, why });
                if (failures.get(.damaged) <= max_report) try dumpFrame(ctx, i, mode, base, buf.items);
            } else ok(.damaged);
        }
    }
}

/// The frame a `damaged` mismatch was found on, for a repro: the frame, and
/// its dictionary if it had one, under `.zig-cache/interop-zstd/damaged/`.
fn dumpFrame(ctx: *Ctx, i: usize, mode: u8, base: SmallFrame, frame: []const u8) !void {
    const io = ctx.peer.io;
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, scratch ++ "/damaged");
    var nbuf: [128]u8 = undefined;
    const name = try std.fmt.bufPrint(&nbuf, scratch ++ "/damaged/s{d}-c{d}-m{d}{s}.zst", .{ ctx.seed, i, mode, if (base.magicless) "-magicless" else "" });
    try cwd.writeFile(io, .{ .sub_path = name, .data = frame });
    if (base.dict.mode != .none) {
        const dname = try std.fmt.bufPrint(&nbuf, scratch ++ "/damaged/s{d}-c{d}-m{d}.{t}", .{ ctx.seed, i, mode, base.dict.mode });
        try cwd.writeFile(io, .{ .sub_path = dname, .data = base.dict.bytes });
    }
}

fn familyTrain(ctx: *Ctx, n: usize) !void {
    const gpa = ctx.gpa;
    var prng: std.Random.DefaultPrng = .init(ctx.seed ^ 0x7A);
    const rnd = prng.random();
    for (0..n) |i| {
        const count = 20 + rnd.uintLessThan(usize, 400);
        const sizes = try gpa.alloc(usize, count);
        defer gpa.free(sizes);
        var total: usize = 0;
        for (sizes) |*s| {
            s.* = 16 + genSize(rnd, 4096);
            total += s.*;
        }
        const samples = try gpa.alloc(u8, total);
        defer gpa.free(samples);
        // samples of one kind share structure, as a real training set does
        var off: usize = 0;
        const kind = rnd.uintLessThan(u8, 6);
        for (sizes) |s| {
            fillKind(rnd, samples[off..][0..s], if (kind == 5) rnd.uintLessThan(u8, 5) else kind);
            off += s;
        }
        const cap: u32 = 256 + rnd.uintLessThan(u32, 64 << 10);
        const theirs = try ctx.peer.train(cap, sizes, samples);
        defer freeReply(gpa, theirs);
        const dict = try gpa.alloc(u8, cap);
        defer gpa.free(dict);
        const ours: Ours = if (zstd.dict_builder.train(gpa, dict, .{ .buffer = samples, .sizes = sizes })) |m|
            .{ .ok = try gpa.dupe(u8, dict[0..m]) }
        else |e|
            .{ .err = e };
        defer freeOurs(gpa, ours);
        var dbuf: [160]u8 = undefined;
        if (differ(&dbuf, ours, theirs)) |why| {
            bad(.train, "case {d} seed {d}: {d} samples, {d} B, capacity {d}, kind {d}: {s}", .{ i, ctx.seed, count, total, cap, kind, why });
        } else ok(.train);
        if (theirs == .ok and ctx.dicts.items.len < 16) try ctx.dicts.append(gpa, try gpa.dupe(u8, theirs.ok));
    }
    // raw-content dictionaries too: any bytes
    for (0..4) |_| {
        const d = try genInput(gpa, rnd, 1024 + rnd.uintLessThan(usize, 32 << 10));
        try ctx.dicts.append(gpa, d);
    }
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var src_dir: []const u8 = default_src;
    var seed: u64 = 1;
    var scale: usize = 1;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--zstd-src")) {
            src_dir = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, a, "--seed")) {
            seed = try std.fmt.parseInt(u64, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, a, "--scale")) {
            scale = try std.fmt.parseInt(usize, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, a, "--all")) {
            max_report = std.math.maxInt(usize);
        } else {
            std.debug.print("usage: interop-zstd [--zstd-src DIR] [--seed N] [--scale N] [--all]\n", .{});
            return 2;
        }
    }

    const exe = try buildOracle(gpa, io, src_dir);
    var peer: Peer = .{
        .gpa = gpa,
        .io = io,
        .child = std.process.spawn(io, .{ .argv = &.{exe}, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit }) catch |e| {
            std.debug.print("interop-zstd: could not start {s} ({t})\n", .{ exe, e });
            return error.NoReference;
        },
    };
    peer.start();
    defer peer.stop();
    const v = try peer.version();
    defer freeReply(gpa, v);
    if (v != .ok or !std.mem.eql(u8, v.ok, zstd.version_string)) {
        std.debug.print("interop-zstd: the peer is not libzstd {s}\n", .{zstd.version_string});
        return error.NoReference;
    }
    std.debug.print("interop-zstd: libzstd {s} (pinned {s}), seed {d}, scale {d}\n", .{ v.ok, pinned_commit[0..8], seed, scale });

    var ctx: Ctx = .{ .gpa = gpa, .peer = &peer, .seed = seed };
    defer {
        for (ctx.small.items) |s| gpa.free(s.frame);
        ctx.small.deinit(gpa);
        for (ctx.dicts.items) |d| gpa.free(d);
        ctx.dicts.deinit(gpa);
    }
    var clock = std.Io.Clock.awake.now(io).nanoseconds;
    const phases = [_]struct { []const u8, Family }{
        .{ "train", .train },   .{ "compress", .compress }, .{ "compress+dict", .compress },
        .{ "stream", .stream }, .{ "damaged", .damaged },
    };
    for (phases) |ph| {
        switch (ph[1]) {
            .train => try familyTrain(&ctx, 12 * scale),
            .compress => try familyCompress(&ctx, if (std.mem.eql(u8, ph[0], "compress")) 500 * scale else 150 * scale, !std.mem.eql(u8, ph[0], "compress")),
            .stream => try familyStream(&ctx, 200 * scale),
            .damaged => try familyDamaged(&ctx, 2000 * scale),
            .decode => unreachable,
        }
        const now = std.Io.Clock.awake.now(io).nanoseconds;
        std.debug.print("  {s:<14} done in {d:.1} s\n", .{ ph[0], @as(f64, @floatFromInt(now - clock)) / 1e9 });
        clock = now;
    }

    var total_fail: usize = 0;
    std.debug.print("\n{s:<10} {s:>8} {s:>9} {s:>6}\n", .{ "family", "checks", "mismatch", "gap" });
    for (std.enums.values(Family)) |f| {
        std.debug.print("{t:<10} {d:>8} {d:>9} {d:>6}\n", .{ f, checks.get(f), failures.get(f), gaps.get(f) });
        total_fail += failures.get(f);
    }
    if (total_fail > 0) {
        std.debug.print("\ninterop-zstd: {d} MISMATCH(es) against libzstd -- NOT OK\n", .{total_fail});
        return 1;
    }
    std.debug.print("\ninterop-zstd: OK\n", .{});
    return 0;
}
