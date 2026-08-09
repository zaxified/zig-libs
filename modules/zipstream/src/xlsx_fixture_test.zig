// SPDX-License-Identifier: MIT

//! Offline anchor for the READER half of this module against a genuinely
//! foreign-tool-produced archive — specifically the motivating use case named
//! in README.md ("an .xlsx is a ZIP of XML parts").
//!
//! ## Why this file exists
//!
//! Before this file, every reader test in `root.zig` (`buildZip`/`buildZip64`)
//! fed `Archive`/`EntryReader` bytes hand-assembled *in this repo*, from the
//! same `std.zip` structs the production code parses. `write_golden_test.zig`
//! closes the analogous gap for the *writer* half (an `ArchiveWriter`-made
//! archive externally checked by `unzip`/`zipinfo`), but that fixture is still
//! bytes our own encoder produced — no test in this module had ever pointed
//! `Archive.init` at an archive a real, independent tool actually wrote. That
//! is the "encoder and decoder agree on the same misreading" blind spot,
//! mirrored on the read side: `std.zip.Iterator`'s parsing and this module's
//! own walk both read the same APPNOTE.TXT text the same way, but neither had
//! ever been fed a real spreadsheet application's output. This file closes
//! that gap with a real `.xlsx` (a real ZIP container) captured from
//! LibreOffice Calc.
//!
//! ## Capture recipe (run once; LibreOffice 26.2.4.2, Debian)
//!
//!   1. A 3-line CSV (`name,qty` header + `widget,3` + `gadget,7`) was
//!      converted headless:
//!      `soffice --headless --norestore --convert-to \
//!        xlsx:"Calc MS Excel 2007 XML" sample.csv`
//!   2. Result: `sample.xlsx`, 5676 bytes, 10 members (the standard OOXML
//!      package shape: `[Content_Types].xml`, `_rels/.rels`, `docProps/*`,
//!      `xl/workbook.xml` + its `_rels`, `xl/theme/theme1.xml`,
//!      `xl/styles.xml`, `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml`).
//!      All 10 use Deflate.
//!   3. `unzip -t sample.xlsx` → "No errors detected in compressed data" for
//!      all 10 members (Info-ZIP 6.00, independent of this module and of
//!      LibreOffice).
//!   4. `zipinfo -v sample.xlsx` reported, for every one of the 10 entries,
//!      `extended local header: yes` — LibreOffice streams each member and
//!      writes a **post-data data descriptor** (general-purpose bit 3 set,
//!      `flag_bits = 0x0808`; bit 0x800 is the UTF-8-name flag), so the
//!      *local* file header's own `crc32`/`compressed_size`/`uncompressed_size`
//!      fields are all **zero** — confirmed by hand-parsing the first local
//!      header's raw bytes (offset 0, `xl/_rels/workbook.xml.rels`):
//!      `flag=0x0808 crc=00000000 csize=0 usize=0`. `ArchiveWriter` in this
//!      module never emits a data descriptor (it always knows an entry's
//!      final size before writing the local header — see its doc comment),
//!      so **no self-made fixture could ever exercise this real-world local-
//!      header shape**; only a foreign producer can. This is precisely the
//!      "real-world writers" case the module's own design note calls out
//!      ("Local header, not central" in README.md/SPEC.md): `EntryReader`
//!      never reads size/CRC out of the local header at all, only using it to
//!      locate the *data offset* (`filename_len`/`extra_len`), so the zeroed
//!      local fields are irrelevant to it by construction — this fixture is
//!      what actually exercises that design decision against a producer that
//!      needs it, instead of just against hand-built bytes that happen not to
//!      contradict it.
//!   5. Central-directory CRC-32/sizes for the two members this file asserts
//!      against (captured independently via `zipinfo -v`, not this module's
//!      own encoder — there is no encoder involved on the read side at all):
//!      `xl/sharedStrings.xml`: crc32 `72036c90`, compressed 183, uncompressed
//!      326 bytes. `xl/worksheets/sheet1.xml`: crc32 `85dd2fb9`, compressed
//!      1048, uncompressed 2798 bytes.
//!
//! `testdata/xlsx_sample.xlsx` is a genuinely valid, independently
//! inspectable ZIP/OOXML package — `unzip -l`/`zipinfo -v`/`unzip -p` on it
//! with any real ZIP implementation reproduces the facts above. Regenerate by
//! rerunning the capture steps (LibreOffice must be installed; this is a
//! manual, offline-afterward capture — the committed bytes are the fixture,
//! no build-time tool invocation is added).
//!
//! Not covered here: parsing the OOXML XML content itself (out of scope for a
//! ZIP-layer module — `zipstream` only needs to prove it can list and stream
//! the members of a real `.xlsx`; the payload assertions below just confirm
//! the streamed bytes are the exact original XML, via a plain substring/CRC
//! check, not an XML parse).

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");
const Archive = zs.Archive;
const EntryReader = zs.EntryReader;

const xlsx: []const u8 = @embedFile("testdata/xlsx_sample.xlsx");

fn openFixture(tmp: *testing.TmpDir) !std.Io.File {
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "sample.xlsx", .data = xlsx });
    return tmp.dir.openFile(testing.io, "sample.xlsx", .{});
}

// ── fixture canary ──────────────────────────────────────────────────────────

test "xlsx fixture: size canary (LibreOffice-produced sample.xlsx)" {
    try testing.expectEqual(@as(usize, 5676), xlsx.len);
}

// ── local header really carries a data descriptor (zeroed size/CRC fields)
//    — the real-world shape no self-made fixture in this module produces ────

test "xlsx fixture: LibreOffice's local file header uses a data descriptor (zeroed size/CRC fields), unlike anything ArchiveWriter emits" {
    var r: std.Io.Reader = .fixed(xlsx);
    const lfh = try r.takeStruct(std.zip.LocalFileHeader, .little);
    try testing.expectEqualSlices(u8, &std.zip.local_file_header_sig, &lfh.signature);
    // General-purpose bit 3 (0x0008) = data descriptor follows the data;
    // bit 11 (0x0800) = UTF-8 filename. Real producers set this; this
    // module's own ArchiveWriter never does (it always knows the final size
    // before the local header is written). `std.zip.LocalFileHeader.flags`
    // only models bit 0 (`encrypted`) and leaves the rest as reserved bits,
    // so the full 16-bit field is recovered via @bitCast for this check.
    try testing.expectEqual(@as(u16, 0x0808), @as(u16, @bitCast(lfh.flags)));
    try testing.expectEqual(@as(u32, 0), lfh.crc32);
    try testing.expectEqual(@as(u32, 0), lfh.compressed_size);
    try testing.expectEqual(@as(u32, 0), lfh.uncompressed_size);
}

// ── Archive.init walks a real package's central directory ─────────────────

test "Archive.init walks a real .xlsx's central directory: 10 members, all content (no dir entries), known names present" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openFixture(&tmp);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    try testing.expectEqual(@as(usize, 10), archive.entries.items.len);
    for (archive.entries.items) |e| {
        try testing.expect(e.name.len > 0 and e.name[e.name.len - 1] != '/');
        try testing.expectEqual(std.zip.CompressionMethod.deflate, e.compression);
    }

    try testing.expect(archive.find("[Content_Types].xml") != null);
    try testing.expect(archive.find("_rels/.rels") != null);
    try testing.expect(archive.find("xl/workbook.xml") != null);
    try testing.expect(archive.find("xl/sharedStrings.xml") != null);
    try testing.expect(archive.findSuffix("worksheets/sheet1.xml") != null);
}

// ── EntryReader decodes real Deflate members back to the exact original XML

test "EntryReader decodes xl/sharedStrings.xml from the real fixture: exact bytes, independently-captured CRC-32" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openFixture(&tmp);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    const entry = archive.find("xl/sharedStrings.xml").?;
    try testing.expectEqual(@as(u64, 183), entry.compressed_size);
    try testing.expectEqual(@as(u64, 326), entry.uncompressed_size);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, entry, &window);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try er.reader().appendRemaining(a, &out, .unlimited);

    try testing.expectEqual(@as(usize, 326), out.items.len);
    // Pinned from `zipinfo -v` at capture time (see doc comment above),
    // recomputed here via std.hash.Crc32 — independent of this module's read
    // path (the CRC-32 the archive itself reports is never consulted).
    try testing.expectEqual(@as(u32, 0x72036c90), std.hash.Crc32.hash(out.items));
    // `EntryReader`'s own CRC-32 verification (audit F4) also ran during the
    // read above and agreed — proof it works against a real writer's local
    // header with zeroed crc/sizes (LibreOffice's data-descriptor shape, see
    // this file's doc comment), not just against this module's own encoder.
    try testing.expect(!er.crcMismatch());

    // The shared-strings table for the source CSV (name,qty / widget,3 /
    // gadget,7) must literally contain these four values as XML text.
    try testing.expect(std.mem.indexOf(u8, out.items, "<t xml:space=\"preserve\">name</t>") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "<t xml:space=\"preserve\">qty</t>") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "<t xml:space=\"preserve\">widget</t>") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "<t xml:space=\"preserve\">gadget</t>") != null);
}

test "EntryReader decodes xl/worksheets/sheet1.xml from the real fixture: exact size + independently-captured CRC-32" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openFixture(&tmp);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    const entry = archive.find("xl/worksheets/sheet1.xml").?;
    try testing.expectEqual(@as(u64, 1048), entry.compressed_size);
    try testing.expectEqual(@as(u64, 2798), entry.uncompressed_size);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, entry, &window);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try er.reader().appendRemaining(a, &out, .unlimited);

    try testing.expectEqual(@as(usize, 2798), out.items.len);
    try testing.expectEqual(@as(u32, 0x85dd2fb9), std.hash.Crc32.hash(out.items));
    try testing.expect(std.mem.indexOf(u8, out.items, "<worksheet") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "dimension ref=\"A1:B3\"") != null);
    try testing.expect(!er.crcMismatch());
}
