// SPDX-License-Identifier: MIT
//
// Hand-run instrument (NOT part of `zig build test`): runs the real W3C XML
// Conformance Test Suite, fetched by `xmlconf_fetch.sh` into the gitignored
// `xmlconf-suite/`, through `xml.parse`. Nothing of the suite is committed;
// this program only reads the copy the developer downloaded.
//
//   modules/xml/tools/xmlconf_fetch.sh
//   zig build-exe -O ReleaseSafe --dep xml -Mmain=modules/xml/tools/xmlconf_run.zig \
//       -Mxml=modules/xml/src/root.zig --cache-dir <scratch>/zc -femit-bin=<scratch>/xmlconf_run
//   <scratch>/xmlconf_run [suite dir]       # default: modules/xml/tools/xmlconf-suite/xmlconf
//
// Why a hand-written scanner and not `xml.parse` for the manifests: the
// sub-manifests are fragments (several top-level elements, entity-included
// by xmlconf.xml), not documents.
//
// What is run, mirroring what the in-tree vendored test did before 2026-10-24:
//   TYPE="not-wf"  files without a DOCTYPE, under default Options. A DOCTYPE-
//                  bearing not-wf case is skipped: `doctype = .reject` would
//                  refuse it before its labeled defect is looked at.
//   TYPE="valid"   under `Options{ .doctype = .ignore }`.
// Skipped by TYPE: "invalid" (a DTD validity constraint; this parser does not
// validate) and "error" (optional conditions). Skipped by scope: XML/NS 1.1,
// tests that apply only to editions before the 5th, NAMESPACE="no" cases.
// A valid case that fails only because of a documented design limit is counted
// as OUT-OF-SCOPE, not as a failure:
//   UndefinedEntity in a document with a DOCTYPE   (user-declared entities are
//                                                   never expanded under .ignore)
//   UnsupportedEncoding                            (UTF-8/16, Latin-1, ASCII only)
//
// Exit status 1 when any verdict is neither expected nor listed in
// `known_disagreements`, or when a listed disagreement has stopped happening.

const std = @import("std");
const xml = @import("xml");

/// Sub-manifests that are read (paths relative to the suite dir). The test
/// files named inside are relative to the manifest's own directory.
const manifests = [_][]const u8{
    "sun/sun-valid.xml",
    "sun/sun-not-wf.xml",
    "ibm/ibm_oasis_valid.xml",
    "ibm/ibm_oasis_not-wf.xml",
    "eduni/namespaces/1.0/rmt-ns10.xml",
    "eduni/namespaces/errata-1e/errata1e.xml",
    "eduni/errata-2e/errata2e.xml",
    "eduni/errata-3e/errata3e.xml",
    "eduni/errata-4e/errata4e.xml",
    "oasis/oasis.xml",
    "xmltest/xmltest.xml",
};

const Disagreement = struct {
    id: []const u8,
    /// true: a not-wf case that this module parses; false: a valid case it refuses.
    parses_but_not_wf: bool,
    why: []const u8,
};

/// Real disagreements between this module and the suite, found by running it
/// and NOT fixed. The old in-tree list (vendored slice) was empty; this one is
/// from the first run against the full suite on 2026-10-24 (2164 manifest entries).
const known_disagreements = [_]Disagreement{
    .{
        .id = "x-rmt-008b",
        .parses_but_not_wf = false,
        .why = "XML 1.0 5th ed. allows any 1.x VersionNum (here 1.7); this module " ++
            "refuses every version but 1.0 (UnsupportedVersion) -- the strict direction",
    },
};

fn isKnown(id: []const u8, parses_but_not_wf: bool) ?Disagreement {
    for (known_disagreements) |k| {
        if (k.parses_but_not_wf == parses_but_not_wf and std.mem.eql(u8, k.id, id)) return k;
    }
    return null;
}

const Test = struct {
    id: []const u8 = "",
    uri: []const u8 = "",
    kind: []const u8 = "",
    version: ?[]const u8 = null,
    recommendation: ?[]const u8 = null,
    edition: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
};

fn hasToken(list: []const u8, token: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, list, " \t\r\n");
    while (it.next()) |t| if (std.mem.eql(u8, t, token)) return true;
    return false;
}

/// Reads the next `<TEST ...>` start tag at or after `pos`; null at the end.
fn nextTest(src: []const u8, pos: *usize) ?Test {
    while (std.mem.indexOfPos(u8, src, pos.*, "<TEST")) |at| {
        const after = at + "<TEST".len;
        pos.* = after;
        if (after >= src.len or !std.ascii.isWhitespace(src[after])) continue; // <TESTCASES, <TESTSUITE
        var t: Test = .{};
        var i = after;
        while (i < src.len and src[i] != '>') {
            while (i < src.len and std.ascii.isWhitespace(src[i])) i += 1;
            if (i >= src.len or src[i] == '>' or src[i] == '/') break;
            const name_start = i;
            while (i < src.len and src[i] != '=' and !std.ascii.isWhitespace(src[i]) and src[i] != '>') i += 1;
            const name = src[name_start..i];
            while (i < src.len and std.ascii.isWhitespace(src[i])) i += 1;
            if (i >= src.len or src[i] != '=') continue;
            i += 1;
            while (i < src.len and std.ascii.isWhitespace(src[i])) i += 1;
            if (i >= src.len or (src[i] != '"' and src[i] != '\'')) continue;
            const q = src[i];
            i += 1;
            const v_start = i;
            while (i < src.len and src[i] != q) i += 1;
            const value = src[v_start..@min(i, src.len)];
            i += 1;
            if (std.mem.eql(u8, name, "ID")) t.id = value;
            if (std.mem.eql(u8, name, "URI")) t.uri = value;
            if (std.mem.eql(u8, name, "TYPE")) t.kind = value;
            if (std.mem.eql(u8, name, "VERSION")) t.version = value;
            if (std.mem.eql(u8, name, "RECOMMENDATION")) t.recommendation = value;
            if (std.mem.eql(u8, name, "EDITION")) t.edition = value;
            if (std.mem.eql(u8, name, "NAMESPACE")) t.namespace = value;
        }
        pos.* = @min(i, src.len);
        return t;
    }
    return null;
}

const Counts = struct {
    pass: usize = 0,
    known: usize = 0,
    fail: usize = 0,
    skip_type: usize = 0,
    skip_version: usize = 0,
    skip_edition: usize = 0,
    skip_namespace: usize = 0,
    skip_doctype: usize = 0,
    out_of_scope_entity: usize = 0,
    out_of_scope_encoding: usize = 0,
    missing: usize = 0,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const suite: []const u8 = if (args.len > 1) args[1] else "modules/xml/tools/xmlconf-suite/xmlconf";
    const cwd = std.Io.Dir.cwd();

    var c: Counts = .{};
    var total_tests: usize = 0;

    for (manifests) |m| {
        var path_buf: [1024]u8 = undefined;
        const mpath = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ suite, m });
        const msrc = cwd.readFileAlloc(io, mpath, gpa, .limited(1 << 26)) catch |e| {
            std.debug.print("cannot read manifest {s}: {t} (run tools/xmlconf_fetch.sh first)\n", .{ mpath, e });
            std.process.exit(2);
        };
        defer gpa.free(msrc);
        const mdir = std.fs.path.dirname(m) orelse "";
        var pos: usize = 0;
        while (nextTest(msrc, &pos)) |t| {
            total_tests += 1;
            const is_valid = std.mem.eql(u8, t.kind, "valid");
            const is_notwf = std.mem.eql(u8, t.kind, "not-wf");
            if (!is_valid and !is_notwf) {
                c.skip_type += 1;
                continue;
            }
            if (t.version) |v| if (!hasToken(v, "1.0")) {
                c.skip_version += 1;
                continue;
            };
            if (t.recommendation) |r| if (std.mem.indexOf(u8, r, "1.1") != null) {
                c.skip_version += 1;
                continue;
            };
            if (t.edition) |e| if (!hasToken(e, "5")) {
                c.skip_edition += 1;
                continue;
            };
            if (is_valid) if (t.namespace) |n| if (std.mem.eql(u8, n, "no")) {
                c.skip_namespace += 1;
                continue;
            };

            var fbuf: [2048]u8 = undefined;
            const fpath = try std.fmt.bufPrint(&fbuf, "{s}/{s}/{s}", .{ suite, mdir, t.uri });
            const src = cwd.readFileAlloc(io, fpath, gpa, .limited(1 << 26)) catch {
                std.debug.print("MISSING {s} ({s})\n", .{ t.id, fpath });
                c.missing += 1;
                continue;
            };
            defer gpa.free(src);
            const has_doctype = std.mem.indexOf(u8, src, "<!DOCTYPE") != null;

            if (is_notwf) {
                if (has_doctype) {
                    c.skip_doctype += 1;
                    continue;
                }
                if (xml.parse(gpa, src, .{})) |d| {
                    var doc = d;
                    doc.deinit();
                    if (isKnown(t.id, true) != null) {
                        c.known += 1;
                    } else {
                        std.debug.print("UNEXPECTED not-wf {s} ({s}): parsed\n", .{ t.id, t.uri });
                        c.fail += 1;
                    }
                } else |_| {
                    if (isKnown(t.id, true) != null) {
                        std.debug.print("STALE known_disagreements entry {s}: now rejected, remove it\n", .{t.id});
                        c.fail += 1;
                    } else c.pass += 1;
                }
            } else {
                if (xml.parse(gpa, src, .{ .doctype = .ignore })) |d| {
                    var doc = d;
                    doc.deinit();
                    if (isKnown(t.id, false) != null) {
                        std.debug.print("STALE known_disagreements entry {s}: now parses, remove it\n", .{t.id});
                        c.fail += 1;
                    } else c.pass += 1;
                } else |e| {
                    if (e == error.UndefinedEntity and has_doctype) {
                        c.out_of_scope_entity += 1;
                    } else if (e == error.UnsupportedEncoding) {
                        c.out_of_scope_encoding += 1;
                    } else if (isKnown(t.id, false) != null) {
                        c.known += 1;
                    } else {
                        std.debug.print("UNEXPECTED valid {s} ({s}): {t}\n", .{ t.id, t.uri, e });
                        c.fail += 1;
                    }
                }
            }
        }
    }

    std.debug.print(
        "xmlconf: tests={d} pass={d} known={d} FAIL={d} | out-of-scope: entity={d} encoding={d} | " ++
            "skipped: type={d} version={d} edition={d} namespace={d} doctype={d} | missing={d}\n",
        .{
            total_tests,           c.pass,                  c.known,        c.fail,
            c.out_of_scope_entity, c.out_of_scope_encoding, c.skip_type,    c.skip_version,
            c.skip_edition,        c.skip_namespace,        c.skip_doctype, c.missing,
        },
    );
    if (c.fail != 0 or c.missing != 0) std.process.exit(1);
}
