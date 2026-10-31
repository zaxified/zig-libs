// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GY), findings UC-1 .. UC-3; see
//! ~/CML/20261029-panic-sweep/uci-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const uci = @import("root.zig");

fn threadCpuNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.THREAD_CPUTIME_ID, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// `config t 's0'` ... `config t 's<n-1>'`
fn namedSections(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    for (0..n) |i| try buf.print(gpa, "config t 's{d}'\n", .{i});
    return buf.toOwnedSlice(gpa);
}

// ── UC-1: Editor growth is capped, lookups are indexed, delta work is bounded ──

test "Editor: growth stops exactly at max_total_items (sweep UC-1)" {
    const gpa = testing.allocator;
    var pkg: uci.Package = .{};
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    const root = try ed.add("t"); // 1 item
    var key_buf: [16]u8 = undefined;
    // 149_999 options x 2 items + the section = 299_999 items.
    for (0..149_999) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "k{d}", .{i});
        try ed.set(root, key, "v");
    }
    try testing.expectEqual(uci.max_total_items - 1, ed.items);
    _ = try ed.add("t"); // exactly the cap
    try testing.expectEqual(uci.max_total_items, ed.items);
    try testing.expectError(error.MemoryLimitExceeded, ed.add("t"));
    try testing.expectError(error.MemoryLimitExceeded, ed.setSection("extra", "t"));
    try testing.expectError(error.MemoryLimitExceeded, ed.set(root, "knew", "v"));
    try testing.expectError(error.MemoryLimitExceeded, ed.addList(root, "knew", "v"));
    try testing.expectError(error.MemoryLimitExceeded, ed.addList(root, "k0", "v"));
    // Replacing a value does not grow, and a refused call changed nothing.
    try ed.set(root, "k0", "w");
    try testing.expectEqual(uci.max_total_items, ed.items);
    // Removing frees room again, and the count follows every kind of removal.
    try ed.deleteOption(root, "k1");
    try testing.expectEqual(uci.max_total_items - 2, ed.items);
    try ed.addList(root, "knew", "a");
    try testing.expectEqual(uci.max_total_items, ed.items);
    try testing.expectError(error.MemoryLimitExceeded, ed.addList(root, "knew", "b"));
    try ed.delList(root, "knew", "a");
    try testing.expectEqual(uci.max_total_items - 1, ed.items);
    try ed.addList(root, "knew", "b");
    try testing.expectError(error.MemoryLimitExceeded, ed.addList(root, "knew", "c"));
    try ed.delete(root);
    try testing.expectEqual(@as(usize, 1), ed.items); // the second section
    // The editor is still a valid package at the cap boundary.
    var out = try ed.toPackage(gpa);
    out.deinit(gpa);
}

test "applyDelta: records past max_total_items stop with MemoryLimitExceeded at that record (sweep UC-1)" {
    const gpa = testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..uci.max_total_items + 1) |i| try text.print(gpa, "+p.cfg{d}='t'\n", .{i});
    var pkg: uci.Package = .{};
    var diag: uci.Diagnostics = .{};
    try testing.expectError(error.MemoryLimitExceeded, uci.applyDelta(gpa, &pkg, "p", text.items, &diag));
    try testing.expectEqual(uci.max_total_items + 1, diag.line);
    // The cap itself is accepted.
    const cut = std.mem.findScalarLast(u8, text.items[0 .. text.items.len - 1], '\n').? + 1;
    var ok = try uci.applyDelta(gpa, &pkg, "p", text.items[0..cut], &diag);
    defer ok.deinit(gpa);
    try testing.expectEqual(uci.max_total_items, ok.sections.len);
}

test "applyDelta: id and key lookups are indexed, so ordinary records cost O(1) work (sweep UC-1)" {
    const gpa = testing.allocator;
    const n = 20_000;
    const cfg = try namedSections(gpa, n);
    defer gpa.free(cfg);
    var pkg = try uci.parse(gpa, cfg);
    defer pkg.deinit(gpa);
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..n) |i| try text.print(gpa, "p.s{d}.k='v'\n", .{i});
    try ed.applyDelta("p", text.items, null);
    // Linear scans would be ~n*n/2 = 2e8 > max_delta_work (and an error).
    try testing.expect(ed.work < 20 * n);

    // One section with n options: set on existing keys is indexed as well.
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(gpa);
    for (0..n) |i| try one.print(gpa, "p.s0.o{d}='1'\n", .{i});
    try ed.applyDelta("p", one.items, null);
    const before = ed.work;
    try ed.applyDelta("p", one.items, null); // every key now exists
    try testing.expect(ed.work - before < 20 * n);
}

test "applyDelta: structural records are charged and stop at max_delta_work (sweep UC-1)" {
    const gpa = testing.allocator;
    const n = 20_000;
    const cfg = try namedSections(gpa, n);
    defer gpa.free(cfg);
    var pkg = try uci.parse(gpa, cfg);
    defer pkg.deinit(gpa);

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    // Each reorder moves ~n sections and invalidates the id index.
    for (0..2000) |_| try text.print(gpa, "^p.s{d}='0'\n", .{n - 1});

    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    var diag: uci.Diagnostics = .{};
    try testing.expectError(error.WorkLimitExceeded, ed.applyDelta("p", text.items, &diag));
    // ~80k work per record: the cap (2^26) is hit after roughly 800 records.
    try testing.expect(diag.line > 400 and diag.line < 1600);
    try testing.expect(ed.work > uci.max_delta_work);
    try testing.expect(ed.work < uci.max_delta_work + 400_000); // overshoot: at most one record

    // 100 of the same records are well inside the cap.
    var ed2 = try uci.Editor.init(gpa, &pkg);
    defer ed2.deinit();
    const first_100 = text.items[0 .. 100 * (text.items.len / 2000)];
    try ed2.applyDelta("p", first_100, null);
    try testing.expect(ed2.work < uci.max_delta_work / 4);
}

// ── UC-2: del_list is linear ────────────────────────────────────────────────

test "delList removing every entry of a long list is linear (sweep UC-2)" {
    const gpa = testing.allocator;
    var pkg: uci.Package = .{};
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    const s = try ed.add("t");
    const n = 150_000;
    for (0..n) |_| try ed.addList(s, "l", "x");
    try ed.addList(s, "l", "keep");
    const t0 = threadCpuNs();
    try ed.delList(s, "l", "x");
    const spent = threadCpuNs() - t0;
    // Entry-by-entry removal moved the tail each time: ~1e11 bytes, tens of seconds.
    try testing.expect(spent < 2 * std.time.ns_per_s);
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), out.sections[0].options[0].values.len);
    try testing.expectEqualStrings("keep", out.sections[0].options[0].values[0]);
}

// ── UC-3: show with @type[N] is linear ──────────────────────────────────────

test "show: @type[N] over many anonymous sections is linear (sweep UC-3)" {
    const gpa = testing.allocator;
    const n = 150_000;
    var cfg: std.ArrayList(u8) = .empty;
    defer cfg.deinit(gpa);
    for (0..n) |_| try cfg.appendSlice(gpa, "config t\n");
    var pkg = try uci.parse(gpa, cfg.items);
    defer pkg.deinit(gpa);
    const t0 = threadCpuNs();
    const text = try uci.show(gpa, &pkg, "p", .{});
    defer gpa.free(text);
    const spent = threadCpuNs() - t0;
    // Rescanning the earlier sections for each one: ~1e10 type compares.
    try testing.expect(spent < 3 * std.time.ns_per_s);
    try testing.expect(std.mem.startsWith(u8, text, "p.@t[0]=t\np.@t[1]=t\n"));
    try testing.expect(std.mem.endsWith(u8, text, "p.@t[149999]=t\n"));
}

test "show: @type[N] counts named sections of the type too (sweep UC-3)" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config t\nconfig t 'b'\nconfig u\nconfig t\nconfig u\n");
    defer pkg.deinit(gpa);
    const text = try uci.show(gpa, &pkg, "p", .{});
    defer gpa.free(text);
    try testing.expectEqualStrings("p.@t[0]=t\np.b=t\np.@u[0]=u\np.@t[2]=t\np.@u[1]=u\n", text);
}

test "structural edits are charged for the elements they move (sweep UC-1)" {
    const gpa = testing.allocator;
    const n = 1000;
    const cfg = try namedSections(gpa, n);
    defer gpa.free(cfg);
    var pkg = try uci.parse(gpa, cfg);
    defer pkg.deinit(gpa);
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    for (0..100) |i| {
        var kb: [8]u8 = undefined;
        try ed.addList("s7", std.fmt.bufPrint(&kb, "o{d}", .{i}) catch unreachable, "v");
    }
    for (0..100) |_| try ed.addList("s8", "l", "v");
    try ed.set("s9", "k", "v"); // primes the id index

    var before = ed.work;
    try ed.reorder("s1", 900);
    try testing.expect(ed.work - before >= 3 * 900); // remove + insert + rebuild bookkeeping
    try ed.set("s9", "k", "v"); // re-primes the id index (charged separately)
    before = ed.work;
    try ed.delete("s2");
    try testing.expect(ed.work - before >= 900);
    try ed.set("s9", "k", "v");
    before = ed.work;
    try ed.deleteOption("s7", "o0");
    try testing.expect(ed.work - before >= 90);
    before = ed.work;
    const items_before = ed.items;
    try ed.deleteListItem("s8", "l", 0);
    try testing.expect(ed.work - before >= 90);
    try testing.expectEqual(items_before - 1, ed.items);
    before = ed.work;
    try ed.delList("s8", "l", "v");
    try testing.expect(ed.work - before >= 90);
}

// ── RV-UC-2: lookups are charged by bytes too ───────────────────────────────

test "work counter charges comparisons and hashing by bytes (sweep RV-UC-2)" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config t 'a0'\nconfig t 'a1'\nconfig t 'a2'\nconfig t 'a3'\n");
    defer pkg.deinit(gpa);
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    var long_buf: [6400]u8 = @splat('L'); // 100 x 64 bytes
    const long: []const u8 = &long_buf;
    // findScan: 4 sections, a 6400-byte reference -> >= 4 * 100.
    var before = ed.work;
    try testing.expectError(error.NoSuchSection, ed.delete(long));
    try testing.expect(ed.work - before >= 4 * 100);
    // optIndex linear scan: 10 options, a long key.
    for (0..10) |i| {
        var kb: [8]u8 = undefined;
        try ed.set("a0", try std.fmt.bufPrint(&kb, "o{d}", .{i}), "1");
    }
    before = ed.work;
    try ed.deleteOption("a0", long);
    try testing.expect(ed.work - before >= 10 * 100);
    // delList: 50 values, a 6400-byte needle.
    for (0..50) |_| try ed.addList("a1", "l", "v");
    before = ed.work;
    try ed.delList("a1", "l", long);
    try testing.expect(ed.work - before >= 50 * 100);
    // Index rebuild hashes the stored ids/keys: 20 sections with 6400-byte names,
    // 20 options with 6400-byte keys.
    var ed2 = try uci.Editor.init(gpa, &pkg);
    defer ed2.deinit();
    for (0..20) |i| {
        var nb: [6400]u8 = @splat('N');
        _ = std.fmt.bufPrint(nb[0..8], "{d:0>8}", .{i}) catch unreachable;
        try ed2.setSection(&nb, "t");
    }
    ed2.id_ok = false;
    before = ed2.work;
    try ed2.set("a0", "k", "1"); // rebuilds the id index over 24 sections
    try testing.expect(ed2.work - before >= 20 * 100);
    for (0..20) |i| {
        var kb: [6400]u8 = @splat('K');
        _ = std.fmt.bufPrint(kb[0..8], "{d:0>8}", .{i}) catch unreachable;
        try ed2.set("a0", &kb, "1");
    }
    // Hit through the index: hashing the 6400-byte reference is charged.
    var nb0: [6400]u8 = @splat('N');
    _ = std.fmt.bufPrint(nb0[0..8], "{d:0>8}", .{0}) catch unreachable;
    before = ed2.work;
    try ed2.set(&nb0, "k", "3");
    try testing.expect(ed2.work - before >= 100);
    var kb0: [6400]u8 = @splat('K');
    _ = std.fmt.bufPrint(kb0[0..8], "{d:0>8}", .{0}) catch unreachable;
    before = ed2.work;
    try ed2.set("a0", &kb0, "9"); // option index hit with a long key
    try testing.expect(ed2.work - before >= 100);
    ed2.sections.items[0].omap_ok = false;
    before = ed2.work;
    try ed2.set("a0", "k", "2"); // rebuild of the option index
    try testing.expect(ed2.work - before >= 20 * 100);
}

// ── delta audit GY-A: gaps found by the mutation run ────────────────────────

fn editorOf(gpa: std.mem.Allocator, pkg: *uci.Package, text: []const u8) !uci.Editor {
    pkg.* = try uci.parse(gpa, text);
    return uci.Editor.init(gpa, pkg);
}

fn keyCount(sec: anytype, key: []const u8) usize {
    var n: usize = 0;
    for (sec.options.items) |o| n += @intFromBool(std.mem.eql(u8, o.key, key));
    return n;
}

test "section index: an added, renamed or `@type[N]` section is found through a live index (sweep audit GY-A1)" {
    const gpa = testing.allocator;
    const text = try namedSections(gpa, 20);
    defer gpa.free(text);
    var pkg: uci.Package = undefined;
    var ed = try editorOf(gpa, &pkg, text);
    defer ed.deinit();
    defer pkg.deinit(gpa);
    try ed.set("s0", "k", "v"); // 20 > 16 sections: the id index is built and live now
    try ed.setSection("fresh", "t"); // appended with the index live
    try ed.set("fresh", "k", "w"); // must be found, not NoSuchSection
    try testing.expectEqual(@as(usize, 1), ed.sections.items[20].options.items.len);
    try ed.rename("s5", "renamed");
    try ed.set("renamed", "k", "v");
    try testing.expectError(error.NoSuchSection, ed.set("s5", "k", "v")); // the old name is gone
    // `@type[N]` is never an index key: it must still resolve with the index live.
    try ed.set("@t[3]", "m", "v");
    try ed.set("@t[-1]", "m", "v");
    try testing.expectEqual(@as(usize, 1), keyCount(ed.sections.items[3], "m"));
    try testing.expectEqual(@as(usize, 1), keyCount(ed.sections.items[20], "m"));
}

test "indexes keep the FIRST of duplicate ids / keys, like the linear scan (sweep audit GY-A2)" {
    const gpa = testing.allocator;
    // Hand-built (parse merges duplicates): 18 distinct sections, then two named "dup".
    var names: [18][8]u8 = undefined;
    var secs: [20]uci.Section = undefined;
    for (0..18) |i| {
        const nm = try std.fmt.bufPrint(&names[i], "s{d}", .{i});
        secs[i] = .{ .type = "t", .name = nm, .anonymous = false, .options = &.{} };
    }
    secs[18] = .{ .type = "A", .name = "dup", .anonymous = false, .options = &.{} };
    secs[19] = .{ .type = "B", .name = "dup", .anonymous = false, .options = &.{} };
    const pkg: uci.Package = .{ .sections = &secs };
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    try ed.setSection("dup", "X"); // builds the index: first of the duplicates wins
    try testing.expectEqualStrings("X", ed.sections.items[18].type);
    try testing.expectEqualStrings("B", ed.sections.items[19].type);
    // Append a section whose generated id equals an existing name, index live.
    var nb: [24]u8 = undefined;
    const clash = uci.anonymousName(&nb, ed.counter + 2, "T");
    try ed.setSection(clash, "orig"); // counter + 1
    const id = try ed.add("T"); // counter + 2: generated id == clash
    try testing.expectEqualStrings(clash, id);
    try ed.setSection(clash, "Z");
    try testing.expectEqualStrings("Z", ed.sections.items[20].type); // the first one
    try testing.expectEqualStrings("T", ed.sections.items[21].type);

    // Option keys: the same for the per-section index.
    var opts: [20]uci.Option = undefined;
    var keys: [18][8]u8 = undefined;
    for (0..18) |i| opts[i] = .{ .key = try std.fmt.bufPrint(&keys[i], "k{d}", .{i}), .kind = .single, .values = &.{"v"} };
    opts[18] = .{ .key = "dup", .kind = .single, .values = &.{"first"} };
    opts[19] = .{ .key = "dup", .kind = .single, .values = &.{"second"} };
    const secs2 = [_]uci.Section{.{ .type = "t", .name = "s", .anonymous = false, .options = &opts }};
    const pkg2: uci.Package = .{ .sections = &secs2 };
    var ed2 = try uci.Editor.init(gpa, &pkg2);
    defer ed2.deinit();
    try ed2.set("s", "dup", "X");
    try testing.expectEqualStrings("X", ed2.sections.items[0].options.items[18].values.items[0]);
    try testing.expectEqualStrings("second", ed2.sections.items[0].options.items[19].values.items[0]);
}

test "option index: no stale entries after a delete or a rename (sweep audit GY-A3)" {
    const gpa = testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try text.appendSlice(gpa, "config t 's'\n");
    for (0..20) |i| try text.print(gpa, "\toption k{d} 'v'\n", .{i});
    var pkg: uci.Package = undefined;
    var ed = try editorOf(gpa, &pkg, text.items);
    defer ed.deinit();
    defer pkg.deinit(gpa);
    try ed.set("s", "k19", "a"); // 20 > 16 options: the option index is built and live
    try ed.deleteOption("s", "k3");
    try ed.set("s", "k10", "NEW"); // k10 moved from 10 to 9: a stale index would hit k11
    const sec = &ed.sections.items[0];
    try testing.expectEqual(@as(usize, 19), sec.options.items.len);
    try testing.expectEqual(@as(usize, 1), keyCount(sec, "k10"));
    try testing.expectEqual(@as(usize, 1), keyCount(sec, "k11"));
    try testing.expectEqual(@as(usize, 0), keyCount(sec, "k3"));
    try ed.renameOption("s", "k5", "kn");
    try ed.set("s", "kn", "V"); // a stale index would not know "kn" and append a second one
    try testing.expectEqual(@as(usize, 1), keyCount(sec, "kn"));
    try testing.expectEqual(@as(usize, 0), keyCount(sec, "k5"));
    try testing.expectEqual(@as(usize, 19), sec.options.items.len);
}

test "work counter: exact charges of the scan / index boundary and of lookups (sweep audit GY-A4)" {
    const gpa = testing.allocator;
    // Scan path: n sections cost n + 1 per lookup; 16 is still the scan.
    for ([_]struct { n: usize, w: u64 }{ .{ .n = 3, .w = 4 + 4 }, .{ .n = 16, .w = 17 + 17 }, .{ .n = 17, .w = 18 + 1 } }) |c| {
        const text = try namedSections(gpa, c.n);
        defer gpa.free(text);
        var pkg: uci.Package = undefined;
        var ed = try editorOf(gpa, &pkg, text);
        defer ed.deinit();
        defer pkg.deinit(gpa);
        ed.work = 0;
        try ed.setSection("s0", "t"); // 17 sections: index rebuild n, then a hit of 1
        try ed.setSection("s0", "t"); // a second lookup
        try testing.expectEqual(c.w, ed.work);
    }
    // Options: (n + 1) per scan up to 16; the 17th option switches to the index.
    for ([_]struct { n: usize, w: u64 }{ .{ .n = 3, .w = 2 * (2 + 4) }, .{ .n = 16, .w = 2 * (2 + 17) }, .{ .n = 17, .w = (2 + 17 + 1) + (2 + 1) } }) |c| {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(gpa);
        try text.appendSlice(gpa, "config t 's'\n");
        for (0..c.n) |i| try text.print(gpa, "\toption k{d} 'v'\n", .{i});
        var pkg: uci.Package = undefined;
        var ed = try editorOf(gpa, &pkg, text.items);
        defer ed.deinit();
        defer pkg.deinit(gpa);
        ed.work = 0;
        try ed.delList("s", "k0", "x"); // not a list: lookups only
        try ed.delList("s", "k0", "x");
        try testing.expectEqual(c.w, ed.work);
    }
}

test "work counter: `@type[N]` scans are charged by sections and by type length (sweep audit GY-A5)" {
    const gpa = testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    const ty: [6400]u8 = @splat('T');
    for (0..20) |_| try text.print(gpa, "config {s}\n", .{&ty});
    var pkg: uci.Package = undefined;
    var ed = try editorOf(gpa, &pkg, text.items);
    defer ed.deinit();
    defer pkg.deinit(gpa);
    ed.work = 0;
    const ref = try std.fmt.allocPrint(gpa, "@{s}[0]", .{&ty});
    defer gpa.free(ref);
    try ed.set(ref, "k", "v");
    // At least the 2 scans over 20 sections, each compare costing 1 + len/64.
    try testing.expect(ed.work >= 2 * 20 * (1 + ty.len / 64));
}

test "items accounting: a new named section counts; the next growth is refused one item early at the cap (sweep audit GY-A6)" {
    const gpa = testing.allocator;
    var pkg: uci.Package = .{};
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    try ed.setSection("a", "t");
    try testing.expectEqual(@as(usize, 1), ed.items);
    try ed.addList("a", "l", "x");
    try testing.expectEqual(@as(usize, 3), ed.items);
    // One item below the cap: a NEW list option needs 2 items (refused), an entry in
    // the existing list needs 1 (accepted).
    ed.items = uci.max_total_items - 1;
    try testing.expectError(error.MemoryLimitExceeded, ed.addList("a", "other", "x"));
    try ed.addList("a", "l", "y");
    try testing.expectEqual(uci.max_total_items, ed.items);
}

test "applyDelta: the work budget is per call, and a record is never free (sweep audit GY-A7)" {
    const gpa = testing.allocator;
    var pkg: uci.Package = .{};
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    // Work from earlier calls does not count against this one.
    ed.work = uci.max_delta_work + 5;
    try ed.applyDelta("p", "p.a=t\np.a.k='v'\n", null);
    // Fresh editor: five records for a missing section: lookup 1 + the record's own 1 each.
    var ed2 = try uci.Editor.init(gpa, &pkg);
    defer ed2.deinit();
    try ed2.applyDelta("p", "-p.a\n-p.b\n-p.c\n-p.d\n-p.e\n", null);
    try testing.expectEqual(@as(u64, 10), ed2.work);
}
