// SPDX-License-Identifier: MIT
//! `/proc/self/mounts` parser — the `fstab`/`mtab`(5)-shaped view: device,
//! mount point, filesystem type, options, in that fixed column order. Pure
//! `parseMounts` never touches I/O; `readMounts` is the thin live-file
//! wrapper. See `mountinfo.zig` for the richer (and, per its own doc
//! comment, generally preferable) source this module also covers.

const std = @import("std");

/// One `/proc/self/mounts` row, already unescaped (see `unescapeOctal`) and
/// allocator-owned — free with `freeAll` or by freeing each field plus the
/// slice.
pub const MountEntry = struct {
    /// First column — a block device path, or a pseudo-name (`tmpfs`,
    /// `cgroup2`, `proc`, …) for filesystems with no backing device.
    device: []u8,
    /// Second column — where it is mounted. May contain any byte including
    /// spaces/tabs/newlines/backslashes; the kernel's `mangle_path` escapes
    /// those as `\ooo` (octal) in the raw file, and this field is already
    /// decoded.
    mount_point: []u8,
    /// Third column — filesystem type (`ext4`, `tmpfs`, `overlay`, …).
    fs_type: []u8,
    /// Fourth column — comma-separated mount options, verbatim (not split;
    /// callers that want `noatime`/`ro`/etc. as a set can
    /// `std.mem.splitScalar(u8, options, ',')`).
    options: []u8,

    pub fn free(self: MountEntry, gpa: std.mem.Allocator) void {
        gpa.free(self.device);
        gpa.free(self.mount_point);
        gpa.free(self.fs_type);
        gpa.free(self.options);
    }
};

pub fn freeAll(gpa: std.mem.Allocator, entries: []MountEntry) void {
    for (entries) |e| e.free(gpa);
    gpa.free(entries);
}

/// Reverses the kernel's `mangle_path` (`fs/seq_file.c`) octal escaping:
/// space, tab, newline and backslash are written back as `\040`, `\011`,
/// `\012`, `\134` respectively when they appear in a path the kernel emits
/// into `/proc/self/mounts` or `/proc/self/mountinfo`. Decoded generically —
/// any `\` followed by exactly three octal digits is treated as that escaped
/// byte, matching the kernel's own reader (`fs/namespace.c`'s mount-table
/// parsing accepts the same general `\ooo` form, not only the four bytes it
/// happens to emit) — a `\` not followed by three octal digits is passed
/// through literally rather than treated as a parse error, since a corrupt
/// or unexpected escape here is not a reason to lose the whole row.
pub fn unescapeOctal(gpa: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '\\' and i + 3 < raw.len and
            isOctalDigit(raw[i + 1]) and isOctalDigit(raw[i + 2]) and isOctalDigit(raw[i + 3]))
        {
            const v = (raw[i + 1] - '0') * 64 + (raw[i + 2] - '0') * 8 + (raw[i + 3] - '0');
            try out.append(gpa, v);
            i += 4;
        } else {
            try out.append(gpa, raw[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(gpa);
}

fn isOctalDigit(c: u8) bool {
    return c >= '0' and c <= '7';
}

/// Parses already-read `/proc/self/mounts`-shaped text (four
/// whitespace-separated columns per line; a fifth/sixth `0 0` dump-frequency
/// / fsck-pass pair from the historical `fstab` shape may follow and is
/// ignored). Offline, no I/O — golden-text tested against real captures. A
/// malformed line (fewer than 4 columns) is skipped, not fatal: one corrupt
/// row should not sink the whole table, matching `procnet`'s parsers.
pub fn parseMounts(gpa: std.mem.Allocator, text: []const u8) ![]MountEntry {
    var out: std.ArrayList(MountEntry) = .empty;
    // NOT `freeAll(gpa, out.toOwnedSlice(gpa) catch &.{})`: toOwnedSlice can
    // itself allocate (to shrink the backing buffer to `items.len`), so on
    // the exact same allocator-failure path this errdefer exists to guard
    // against, that call can *also* fail — the `catch &.{}` then silently
    // substitutes an empty slice and every already-collected entry leaks
    // (caught by the FailingAllocator sweep test below). Free `out.items`
    // directly and `deinit` the backing buffer instead: neither allocates,
    // so this cannot itself fail.
    errdefer {
        for (out.items) |e| e.free(gpa);
        out.deinit(gpa);
    }

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var cols = std.mem.tokenizeAny(u8, line, " \t");
        const device_raw = cols.next() orelse continue;
        const mount_point_raw = cols.next() orelse continue;
        const fs_type_raw = cols.next() orelse continue;
        const options_raw = cols.next() orelse continue;

        const device = unescapeOctal(gpa, device_raw) catch continue;
        errdefer gpa.free(device);
        const mount_point = unescapeOctal(gpa, mount_point_raw) catch {
            gpa.free(device);
            continue;
        };
        errdefer gpa.free(mount_point);
        const fs_type = gpa.dupe(u8, fs_type_raw) catch {
            gpa.free(device);
            gpa.free(mount_point);
            continue;
        };
        errdefer gpa.free(fs_type);
        const options = gpa.dupe(u8, options_raw) catch {
            gpa.free(device);
            gpa.free(mount_point);
            gpa.free(fs_type);
            continue;
        };
        errdefer gpa.free(options);

        try out.append(gpa, .{
            .device = device,
            .mount_point = mount_point,
            .fs_type = fs_type,
            .options = options,
        });
    }
    return out.toOwnedSlice(gpa);
}

/// Reads `/proc/self/mounts` (streaming to EOF — like `procnet`'s
/// `readVirtualFile`, `/proc` files report size 0 from `stat` because they
/// are generated on read, not disk-backed, so a positional whole-file read
/// would come back empty) and parses it. A missing/unreadable file returns
/// `null`, not an error: on a system where `/proc` is not mounted this is a
/// legitimate "no data" rather than a hard failure.
pub fn readMounts(gpa: std.mem.Allocator, io: std.Io) !?[]MountEntry {
    const text = readVirtualFile(gpa, io, "/proc/self/mounts", mount_table_read_limit) orelse return null;
    defer gpa.free(text);
    return try parseMounts(gpa, text);
}

/// Bound on how much of `/proc/self/mounts` is read — generous headroom over
/// any real host's mount table (this repo's dev host: ~4 KiB for 63 mounts)
/// while still bounding allocation against a pathological mount count. Named
/// rather than inline so the number is visible, and so a test can reason
/// about it: past this the read TRUNCATES, it does not fail — see
/// `readVirtualFile`.
pub const mount_table_read_limit = 1024 * 1024;

/// Streaming read of a `/proc`/`/sys` virtual file, bounded by `limit`.
/// Local to this module rather than a shared dependency on `procnet`
/// (SPEC.md explains why: disk usage is a distinct module axis, and this is
/// a handful of lines, not the kind of duplication `testkit` exists for).
/// Same idiom as `procnet.readVirtualFile`: `std.Io.File` has no plain
/// `read` method in 0.16 — go through `File.Reader.initStreaming`, which is
/// also what actually forces `/proc` to be read to EOF rather than trusting
/// a (always-0) `stat` size.
///
/// ⚠ `limit` TRUNCATES; it does not reject. A file longer than `limit` comes
/// back as its first `limit` bytes, with the last line likely cut mid-row —
/// which `parseMounts` then skips as malformed, so the caller gets a SHORT
/// table rather than nothing.
///
/// That is a deliberate repair of the opposite behaviour, and of the same
/// defect `procnet.readVirtualFile` carried (fixed there first): this was
/// `allocRemaining(gpa, .limited(limit)) catch null`, and `allocRemaining`
/// returns `error.StreamTooLong` the moment the limit is reached — so an
/// oversized mount table returned NULL and `readMounts` reported "no data",
/// which its own doc comment reserves for "`/proc` is not mounted". Those
/// two are not the same fact and a caller cannot tell them apart. Measured
/// on this defect: with the cap dropped to 300 bytes, `diskfree-demo`
/// printed "-- 0 filesystem(s) shown." and exited 0 on a host with 63
/// mounts. SPEC.md already promised the behaviour implemented here.
fn readVirtualFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ?[]u8 {
    var dir = std.Io.Dir.cwd();
    var file = dir.openFile(io, path, .{}) catch return null;
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(file, io, &buf);

    var list: std.ArrayList(u8) = .empty;
    fr.interface.appendRemaining(gpa, &list, .limited(limit)) catch |err| switch (err) {
        // Everything read so far is already in `list` (documented contract
        // of `appendRemaining`), and it is the bounded prefix we asked for.
        error.StreamTooLong => {},
        else => {
            list.deinit(gpa);
            return null;
        },
    };
    return list.toOwnedSlice(gpa) catch {
        list.deinit(gpa);
        return null;
    };
}

const testing = std.testing;

test "parseMounts: real kernel capture" {
    const text = @embedFile("testdata/mounts_sample.txt");
    const entries = try parseMounts(testing.allocator, text);
    defer freeAll(testing.allocator, entries);

    try testing.expect(entries.len > 0);
    // First row of the capture is the real sysfs mount.
    try testing.expectEqualStrings("sysfs", entries[0].device);
    try testing.expectEqualStrings("/sys", entries[0].mount_point);
    try testing.expectEqualStrings("sysfs", entries[0].fs_type);

    // Root filesystem row must be present with a real device path.
    var found_root = false;
    for (entries) |e| {
        if (std.mem.eql(u8, e.mount_point, "/")) {
            found_root = true;
            try testing.expectEqualStrings("ext4", e.fs_type);
            try testing.expect(std.mem.startsWith(u8, e.device, "/dev/"));
        }
    }
    try testing.expect(found_root);
}

test "parseMounts: octal-escaped mount point with a space decodes correctly" {
    const text = @embedFile("testdata/mounts_escaped.txt");
    const entries = try parseMounts(testing.allocator, text);
    defer freeAll(testing.allocator, entries);

    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expectEqualStrings("/mnt/My Backup Drive", entries[0].mount_point);
    try testing.expectEqualStrings("/dev/sdb1", entries[0].device);
    try testing.expectEqualStrings("ext4", entries[0].fs_type);

    // Tab and backslash escapes, and a device path itself carrying an escape.
    try testing.expectEqualStrings("/mnt/tab\tin\tname", entries[1].mount_point);
    try testing.expectEqualStrings("/mnt/back\\slash", entries[2].mount_point);
    try testing.expectEqualStrings("/dev/disk/by-label/My\\Label", entries[2].device);
}

test "unescapeOctal: plain text round-trips unchanged" {
    const out = try unescapeOctal(testing.allocator, "/plain/path");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("/plain/path", out);
}

test "unescapeOctal: trailing backslash with no full escape is passed through literally" {
    const out = try unescapeOctal(testing.allocator, "/weird\\path");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("/weird\\path", out);
}

test "parseMounts: malformed line (too few columns) is skipped, not fatal" {
    const text = "sysfs /sys sysfs rw,nosuid 0 0\ngarbage-line-two-cols\n/dev/sda1 / ext4 rw 0 0\n";
    const entries = try parseMounts(testing.allocator, text);
    defer freeAll(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
}

test "parseMounts: empty text yields zero entries, not an error" {
    const entries = try parseMounts(testing.allocator, "");
    defer freeAll(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseMounts: no leak whichever allocation fails, incl. the outer append" {
    // A single well-formed row exercises every allocation parseMounts makes
    // for one entry: unescapeOctal(device), unescapeOctal(mount_point),
    // dupe(fs_type), dupe(options), then `out.append` moving all four into
    // the entries list. `options` had no errdefer, so a failure at that last
    // append leaked it while device/mount_point/fs_type (which DO have
    // errdefers) were correctly freed.
    const text = "sysfs /sys sysfs rw,nosuid 0 0\n";

    // Discover exactly how many allocations one fully successful parse
    // makes, so the sweep below is complete without a guessed bound.
    var counter = std.testing.FailingAllocator.init(testing.allocator, .{});
    const baseline = try parseMounts(counter.allocator(), text);
    freeAll(testing.allocator, baseline);
    const total_allocs = counter.alloc_index;

    // Fail at every possible point in turn, including the very last
    // allocation (the outer `out.append` growth) — `std.testing.allocator`
    // is the real backing store under every FailingAllocator below and
    // reports any leak at test teardown.
    var fail_index: usize = 0;
    while (fail_index <= total_allocs) : (fail_index += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        if (parseMounts(fa.allocator(), text)) |entries| {
            freeAll(testing.allocator, entries);
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
        }
    }
}

// `readMounts` is the live-file entry point a consumer actually reaches for
// (see README's API example) — `parseMounts` alone being tested is exactly
// how this module shipped a compile error in `readVirtualFile`'s body: no
// test forced it to be semantically analysed. `/proc/self/mounts` is
// guaranteed present on any Linux host this module builds for (`meta.platform
// = .linux`), same assumption `statfs.zig`'s live `query("/")` test makes, so
// this runs unconditionally rather than behind a skip.
test "readMounts: live /proc/self/mounts round-trips through the real Io reader" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const entries = try readMounts(testing.allocator, io) orelse
        return error.SkipZigTest; // /proc not mounted — not expected on this module's Linux-only target, but not this test's job to assert that
    defer freeAll(testing.allocator, entries);

    try testing.expect(entries.len > 0);
    var found_root = false;
    for (entries) |e| {
        if (std.mem.eql(u8, e.mount_point, "/")) found_root = true;
    }
    try testing.expect(found_root);
}

test "readVirtualFile: a file past `limit` truncates to the prefix, it does not vanish" {
    // Regression for the same defect `procnet.readVirtualFile` carried (see
    // its test of the same name, fixed there first): this was
    // `allocRemaining(...) catch null`, and `allocRemaining` errors
    // `StreamTooLong` the instant the limit is reached — so an oversized
    // mount table returned NULL and `readMounts` reported the "no data"
    // outcome its doc comment reserves for "`/proc` is not mounted". Measured
    // on the defect: with `mount_table_read_limit` dropped to 300,
    // `diskfree-demo` printed "-- 0 filesystem(s) shown." and exited 0 on a
    // 63-mount host, indistinguishable from a host with no `/proc`.
    //
    // `/proc` cannot be made oversized on demand, so this uses a real file of
    // known length. `readVirtualFile` reads it through the same streaming
    // path it uses for `/proc` (the file's `stat` size is never consulted),
    // which is what makes the substitution fair.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // 100 rows of 10 bytes each.
    var payload: [1000]u8 = undefined;
    for (0..100) |i| _ = std.fmt.bufPrint(payload[i * 10 ..][0..10], "row{d:0>6}\n", .{i}) catch unreachable;
    {
        var f = try tmp.dir.createFile(io, "big.txt", .{});
        defer f.close(io);
        var wbuf: [256]u8 = undefined;
        var w = f.writer(io, &wbuf);
        try w.interface.writeAll(&payload);
        try w.interface.flush();
    }

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/big.txt", .{&tmp.sub_path});

    // Under the limit: the whole file, unchanged.
    const whole = readVirtualFile(testing.allocator, io, path, 4096) orelse
        return error.ReadVirtualFileReturnedNull;
    defer testing.allocator.free(whole);
    try testing.expectEqual(@as(usize, 1000), whole.len);

    // Over it: a non-null, exactly-`limit`-byte prefix — NOT null, and not
    // the whole file either.
    const cut = readVirtualFile(testing.allocator, io, path, 250) orelse
        return error.ReadVirtualFileReturnedNullOnOversizedFile;
    defer testing.allocator.free(cut);
    try testing.expectEqual(@as(usize, 250), cut.len);
    try testing.expectEqualStrings(payload[0..250], cut);
}

// `/proc/self/mounts` is kernel-emitted, but per `procnet`'s own threat-model
// note (SPEC.md) the decode entry point is held to the same "never panic on
// arbitrary input" bar as any wire parser: `/proc` can be bind-mounted/faked
// in a container, and this module's pure `parseMounts` also accepts a
// caller-supplied snapshot file. Allocates, so this runs under
// `std.testing.allocator` with every result freed.
const fuzz_fixture = @embedFile("testdata/mounts_sample.txt");

test "fuzz: parseMounts never panics, OOB or leaks, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseMountsNeverLeaks, .{ .corpus = &.{fuzz_fixture} });
}

fn fuzzParseMountsNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const text = mutateSample(smith, fuzz_fixture, &buf);
    const entries = try parseMounts(testing.allocator, text);
    freeAll(testing.allocator, entries);
}

/// One draw in five is pure arbitrary bytes; the rest starts from the real
/// `/proc/self/mounts` capture and applies a handful of byte-level
/// mutations — arbitrary bytes essentially never spell a well-formed
/// `\ooo` octal escape, so mutating a known-good table exercises
/// `unescapeOctal`'s bounds check far more often than a from-scratch random
/// blob would. Shared shape with `procnet`'s `mutateSample`.
fn mutateSample(smith: *std.testing.Smith, sample: []const u8, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 4) == 0) {
        smith.bytes(buf);
        const len = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
        return buf[0..len];
    }
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    const n_mutations = smith.valueRangeAtMost(u8, 0, 24);
    var i: u8 = 0;
    while (i < n_mutations) : (i += 1) {
        if (len == 0) break;
        buf[smith.index(len)] = smith.value(u8);
    }
    return buf[0..len];
}
