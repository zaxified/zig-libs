// SPDX-License-Identifier: MIT

//! Offline anchor for the WRITER half of this module.
//!
//! Before this file, the write path's strongest external cross-check was
//! documented in SPEC.md ("Verification") as: "Ad hoc (not a standing test —
//! no external-tool dependency added to the suite): a small `ArchiveWriter`-
//! produced archive was verified against the real `unzip`/`zipinfo` (`unzip
//! -t` clean, `unzip -p` byte-exact for both a Store and a Deflate entry)."
//! That check was real but never committed as code — nothing in the repo
//! re-runs it, and no CI run has ever exercised it. This file turns that
//! prose claim into a standing, offline anchor: the exact archive that was
//! checked against real `unzip`/`zipinfo`, captured once and committed, with
//! `ArchiveWriter` asserted to still reproduce it byte-for-byte, no
//! subprocess and no skip path.
//!
//! Capture method (run once; UnZip 6.00 / ZipInfo 3.00, Info-ZIP, Debian):
//!
//!   1. `ArchiveWriter.init` + two `addEntry` calls + `finish()` built the
//!      archive below entirely in-process (Store entry "stored.txt" =
//!      "plain stored payload for the external zip oracle\n", 49 bytes;
//!      Deflate entry "deflated.txt" = 40 repeats of "the quick brown fox
//!      jumps over the lazy dog. ", 1800 bytes uncompressed) and wrote it to
//!      `testdata/write_golden.zip` (327 bytes).
//!   2. `unzip -t testdata/write_golden.zip` → "No errors detected in
//!      compressed data" for both entries.
//!   3. `zipinfo -v testdata/write_golden.zip` → confirmed, independently of
//!      this module's own encoder: EOCD at offset 305, central directory 114
//!      bytes at offset 191 with 2 entries; entry 1 CRC-32 `c36ad053`,
//!      stored, 49/49 bytes; entry 2 CRC-32 `fd76bba4`, deflated, 60/1800
//!      bytes, local header at offset 89.
//!   4. `unzip -p testdata/write_golden.zip stored.txt` and `... deflated.txt`
//!      both byte-exact against the known plaintext (verified via `md5sum`
//!      against the plaintext computed independently in the shell).
//!
//! `testdata/write_golden.zip` is a genuinely valid, independently
//! inspectable ZIP archive — `unzip -l`/`zipinfo -v`/`unzip -p` on it with
//! any real ZIP implementation reproduces the facts above. Nothing here is
//! hand-derived; the offsets asserted below (0/89 local headers, 191/247
//! central directory records, 305 EOCD) come directly from that `zipinfo -v`
//! capture, re-derived independently below from the ZIP spec's own fixed
//! record sizes as a sanity check (see the comment on each offset constant).
//!
//! Regenerate: rerun the capture steps above (see git history of this file
//! for the exact throwaway test used to dump the archive to disk), replace
//! `testdata/write_golden.zip`, and update the offset constants/expected
//! sizes below if the fixture's shape changes. Do not hand-edit the `.zip`.
//!
//! ── on `std.zip.Iterator` as a cross-check ──────────────────────────────
//!
//! The existing round-trip test in root.zig already cross-checks
//! `ArchiveWriter`'s output against `std.zip.Iterator` directly (a
//! genuinely different code path than this module's own `Archive` — it has
//! its own zip64/extra-field handling, written and maintained by the Zig
//! core team, not derived from this module's `Archive`). That is real
//! independent-implementation value: a bug shared between `ArchiveWriter`
//! and this module's own `Archive` (the "consistent bug in both halves"
//! blind spot) would plausibly NOT be shared with `std.zip.Iterator`, so
//! the existing cross-check is kept and not redundant with this file.
//!
//! It is, however, ruled here as **not a substitute** for the real `unzip`/
//! `zipinfo` oracle this file freezes, for two reasons: (1) it is still
//! part of the same language's standard library — comparatively young,
//! developed by a much smaller community than Info-ZIP's decades of
//! production exposure to real-world ZIP producers/consumers, so agreement
//! with it says less about real-world interop than agreement with `unzip`/
//! `zipinfo` does; (2) both `std.zip.Iterator` and this module read the
//! *same* APPNOTE.TXT spec text the same author-community wrote against —
//! a shared misreading of the spec is far more plausible between the two
//! than between either of them and Info-ZIP's independently-maintained,
//! much older codebase. Conclusion: keep both checks, but only the frozen
//! `unzip`/`zipinfo` bytes here count as the genuine external anchor: the
//! std.zip.Iterator cross-check is demoted to "extra internal consistency
//! check", not counted as this module's external oracle.
//!
//! Not covered here, with reasons:
//!   - zip64 (>4 GiB / >65535 entries): `ArchiveWriter` cannot even produce
//!     one (`Error.ZipWriteTooLarge`, see SPEC.md "Backlog"), so there is no
//!     writer output for `unzip`/`zipinfo` to bless. zip64 *reading* is
//!     already covered by `buildZip64` in root.zig (hand-built bytes,
//!     documented there as deliberately not needing a real multi-gigabyte
//!     fixture).
//!   - a data-descriptor / streaming-unknown-size local header (general-
//!     purpose flag bit 3): `ArchiveWriter` never emits one (see its doc
//!     comment: sizes are always known before the local header is written,
//!     by design — no streaming-unknown-size support). On the read side,
//!     `EntryReader.initMax` never even inspects the local header's size
//!     fields — compressed/uncompressed size always come from the already-
//!     walked central directory (see "Design & invariants" in SPEC.md), so
//!     whether some *other* tool's local header carried a data descriptor
//!     is irrelevant to this module's own reader; nothing here would
//!     exercise a code path that doesn't exist.
//!   - encrypted entries: out of scope for both reader and writer (see
//!     SPEC.md "Threat model"); no oracle needed for a format this module
//!     never produces or accepts.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");
const Archive = zs.Archive;
const EntryReader = zs.EntryReader;
const ArchiveWriter = zs.ArchiveWriter;

const golden: []const u8 = @embedFile("testdata/write_golden.zip");

const stored_name = "stored.txt";
const stored_data = "plain stored payload for the external zip oracle\n";
const deflated_name = "deflated.txt";
const deflated_data = "the quick brown fox jumps over the lazy dog. " ** 40;

// Fixed-size ZIP records (APPNOTE.TXT), used to re-derive the offsets below
// independently of `zipinfo -v`'s own report, as a sanity cross-check.
const lfh_fixed_size = @sizeOf(std.zip.LocalFileHeader); // 30
const cdfh_fixed_size = @sizeOf(std.zip.CentralDirectoryFileHeader); // 46
const eocd_fixed_size = @sizeOf(std.zip.EndRecord); // 22

// Local file header offsets.
const lfh1_off: usize = 0;
const lfh2_off: usize = lfh1_off + lfh_fixed_size + stored_name.len + stored_data.len; // 0 + 30 + 10 + 49 = 89
// Central directory offset: end of entry 2's compressed data.
const cd_off: usize = lfh2_off + lfh_fixed_size + deflated_name.len + 60; // 89 + 30 + 12 + 60(compressed) = 191
const cd1_off: usize = cd_off;
const cd2_off: usize = cd1_off + cdfh_fixed_size + stored_name.len; // 191 + 46 + 10 = 247
const eocd_off: usize = cd2_off + cdfh_fixed_size + deflated_name.len; // 247 + 46 + 12 = 305

comptime {
    if (lfh2_off != 89) @compileError("offset drift: re-derive lfh2_off against zipinfo -v's captured 89");
    if (cd_off != 191) @compileError("offset drift: re-derive cd_off against zipinfo -v's captured 191");
    if (eocd_off != 305) @compileError("offset drift: re-derive eocd_off against zipinfo -v's captured 305");
}

fn readStructAt(comptime T: type, bytes: []const u8, off: usize) T {
    var r: std.Io.Reader = .fixed(bytes[off..]);
    return r.takeStruct(T, .little) catch unreachable;
}

// ── encode direction: ArchiveWriter reproduces the real, unzip/zipinfo-
//    verified archive byte-for-byte ────────────────────────────────────────

test "golden: ArchiveWriter reproduces the real unzip/zipinfo-verified archive byte-for-byte" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry(stored_name, stored_data, .{ .method = .store });
    try zw.addEntry(deflated_name, deflated_data, .{ .method = .deflate });
    try zw.finish();

    try testing.expectEqualSlices(u8, golden, aw.writer.buffered());
}

// ── local header vs central directory consistency ─────────────────────────

test "golden: local file headers and central directory records agree with each other and with zipinfo's capture" {
    const lfh1 = readStructAt(std.zip.LocalFileHeader, golden, lfh1_off);
    const cd1 = readStructAt(std.zip.CentralDirectoryFileHeader, golden, cd1_off);
    try testing.expectEqualSlices(u8, &std.zip.local_file_header_sig, &lfh1.signature);
    try testing.expectEqualSlices(u8, &std.zip.central_file_header_sig, &cd1.signature);
    try testing.expectEqual(std.zip.CompressionMethod.store, lfh1.compression_method);
    try testing.expectEqual(std.zip.CompressionMethod.store, cd1.compression_method);
    try testing.expectEqual(lfh1.crc32, cd1.crc32);
    try testing.expectEqual(lfh1.compressed_size, cd1.compressed_size);
    try testing.expectEqual(lfh1.uncompressed_size, cd1.uncompressed_size);
    try testing.expectEqual(@as(u32, stored_data.len), cd1.compressed_size); // store: compressed == uncompressed
    try testing.expectEqual(@as(u32, 0), cd1.local_file_header_offset); // entry 1 is first

    const lfh2 = readStructAt(std.zip.LocalFileHeader, golden, lfh2_off);
    const cd2 = readStructAt(std.zip.CentralDirectoryFileHeader, golden, cd2_off);
    try testing.expectEqualSlices(u8, &std.zip.local_file_header_sig, &lfh2.signature);
    try testing.expectEqualSlices(u8, &std.zip.central_file_header_sig, &cd2.signature);
    try testing.expectEqual(std.zip.CompressionMethod.deflate, lfh2.compression_method);
    try testing.expectEqual(std.zip.CompressionMethod.deflate, cd2.compression_method);
    try testing.expectEqual(lfh2.crc32, cd2.crc32);
    try testing.expectEqual(lfh2.compressed_size, cd2.compressed_size);
    try testing.expectEqual(lfh2.uncompressed_size, cd2.uncompressed_size);
    try testing.expectEqual(@as(u32, deflated_data.len), cd2.uncompressed_size);
    try testing.expect(cd2.compressed_size < deflated_data.len); // genuinely compressed
    try testing.expectEqual(@as(u32, lfh2_off), cd2.local_file_header_offset);
}

// ── CRC32 + sizes, recomputed independently of this module's own encoder ──

test "golden: CRC32 and sizes match the plaintext, recomputed via std.hash.Crc32 (not this module's encoder)" {
    const cd1 = readStructAt(std.zip.CentralDirectoryFileHeader, golden, cd1_off);
    try testing.expectEqual(std.hash.Crc32.hash(stored_data), cd1.crc32);
    try testing.expectEqual(@as(u32, 0xc36ad053), cd1.crc32); // pinned from zipinfo -v's own capture

    const cd2 = readStructAt(std.zip.CentralDirectoryFileHeader, golden, cd2_off);
    try testing.expectEqual(std.hash.Crc32.hash(deflated_data), cd2.crc32);
    try testing.expectEqual(@as(u32, 0xfd76bba4), cd2.crc32); // pinned from zipinfo -v's own capture
    try testing.expectEqual(@as(u32, 60), cd2.compressed_size); // pinned from zipinfo -v's own capture
}

// ── end-of-central-directory record ────────────────────────────────────────

test "golden: end-of-central-directory record matches zipinfo's capture" {
    const eocd = readStructAt(std.zip.EndRecord, golden, eocd_off);
    try testing.expectEqualSlices(u8, &std.zip.end_record_sig, &eocd.signature);
    try testing.expectEqual(@as(u16, 2), eocd.record_count_total);
    try testing.expectEqual(@as(u16, 2), eocd.record_count_disk);
    try testing.expectEqual(@as(u32, 114), eocd.central_directory_size);
    try testing.expectEqual(@as(u32, 191), eocd.central_directory_offset);
    try testing.expectEqual(@as(u16, 0), eocd.comment_len);
    try testing.expectEqual(@as(usize, eocd_off + eocd_fixed_size), golden.len); // EOCD is the last thing in the file
}

// ── std.zip.Iterator: extra internal consistency check (see doc comment
//    above for why this does not count as the external oracle) ────────────

test "golden: std.zip.Iterator independently walks the frozen bytes and agrees with the central directory" {
    // std.zip.Iterator requires a seekable *std.Io.File.Reader, so the
    // frozen bytes are written to a real (tmp) file first, mirroring the
    // existing cross-check pattern in root.zig.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "cross.zip", .data = golden });
    var f = try tmp.dir.openFile(testing.io, "cross.zip", .{});
    defer f.close(testing.io);
    var buf: [64 * 1024]u8 = undefined;
    var fr = f.reader(testing.io, &buf);
    var iter = try std.zip.Iterator.init(&fr);

    var seen_stored = false;
    var seen_deflated = false;
    while (try iter.next()) |e| {
        var name_buf: [32]u8 = undefined;
        try fr.seekTo(e.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
        const nm = name_buf[0..e.filename_len];
        try fr.interface.readSliceAll(nm);
        if (std.mem.eql(u8, nm, stored_name)) {
            seen_stored = true;
            try testing.expectEqual(std.hash.Crc32.hash(stored_data), e.crc32);
        } else if (std.mem.eql(u8, nm, deflated_name)) {
            seen_deflated = true;
            try testing.expectEqual(std.hash.Crc32.hash(deflated_data), e.crc32);
        } else return error.UnexpectedEntry;
    }
    try testing.expect(seen_stored and seen_deflated);
}

// ── decode direction: this module's own Archive/EntryReader recover the
//    exact original content from the frozen, externally-verified bytes ────

test "golden: Archive/EntryReader decode the frozen, unzip-verified bytes back to the exact original content" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "w.zip", .data = golden });
    var f = try tmp.dir.openFile(testing.io, "w.zip", .{});
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 2), archive.entries.items.len);

    var window: [std.compress.flate.max_window_len]u8 = undefined;

    var er1: EntryReader = undefined;
    try er1.init(&archive, archive.find(stored_name).?, &window);
    var out1: std.ArrayList(u8) = .empty;
    defer out1.deinit(a);
    try er1.reader().appendRemaining(a, &out1, .unlimited);
    try testing.expectEqualStrings(stored_data, out1.items);

    var er2: EntryReader = undefined;
    try er2.init(&archive, archive.find(deflated_name).?, &window);
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(a);
    try er2.reader().appendRemaining(a, &out2, .unlimited);
    try testing.expectEqualStrings(deflated_data, out2.items);
}

// ── count / size canary ─────────────────────────────────────────────────────

test "golden: fixture size + entry count canary" {
    try testing.expectEqual(@as(usize, 327), golden.len);
    const eocd = readStructAt(std.zip.EndRecord, golden, eocd_off);
    try testing.expectEqual(@as(u16, 2), eocd.record_count_total);
}
