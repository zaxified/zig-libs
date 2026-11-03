// SPDX-License-Identifier: MIT

//! Checksum files, the format `sha256sum`, `sha512sum`, `b2sum` and friends
//! write and `-c` reads: the GNU form `<hex> <mode><name>` (mode a space for
//! text, `*` for binary; a leading backslash on the line marks an escaped
//! name, `\\` for a backslash and `\n` for a newline) and the BSD "tag" form
//! `ALGO (name) = <hex>` (`--tag`). Blank lines and `#` comment lines are
//! skipped; a trailing `\r` is tolerated (files written on Windows), which
//! `sha256sum` itself would treat as part of the name.
//!
//! `Iterator` parses without allocating (entries borrow the text).
//! `verifyEntry` / `verifyAll` hash the named files with `hashFileIn`, like
//! `sha256sum -c`. Everything here returns an error or a status for hostile
//! input; nothing panics. The GNU form carries no algorithm, so the caller
//! passes the one the file was made with; a BSD tag overrides it.

const std = @import("std");
const root = @import("root.zig");
const Algorithm = root.Algorithm;

/// Longest file name `verifyEntry` unescapes (bytes). Longer is `NameTooLong`.
pub const max_name_len = 4096;

pub const ParseError = error{
    /// Not a checksum line: no digest, bad hex, bad separator, empty name,
    /// bad escape or malformed tag.
    BadLine,
    /// A BSD tag (`ALGO (name) = hex`) whose ALGO this module does not know.
    UnknownTag,
};

/// One parsed line. Slices borrow the text given to `Iterator.init`.
pub const Entry = struct {
    /// Set by a BSD tag; null for the GNU form (the caller knows the algorithm).
    algo: ?Algorithm,
    /// The digest as written (hex digits, any case; length is checked against
    /// the algorithm by `verifyEntry`, not here).
    digest: []const u8,
    /// The name as written, still escaped when `escaped`.
    name: []const u8,
    /// The line began with a backslash: `name` needs `unescapeName`.
    escaped: bool,
    /// GNU binary mode (`*`); BSD lines are binary. Informational on POSIX.
    binary: bool,
    /// 1-based line number in the text.
    line: usize,

    /// The real file name into `out`. Errors: `BadLine` for an escape other
    /// than `\\` and `\n` (or a trailing lone backslash), `ShortBuffer`.
    pub fn unescapeName(e: Entry, out: []u8) error{ BadLine, ShortBuffer }![]const u8 {
        if (!e.escaped) {
            if (out.len < e.name.len) return error.ShortBuffer;
            @memcpy(out[0..e.name.len], e.name);
            return out[0..e.name.len];
        }
        var n: usize = 0;
        var i: usize = 0;
        while (i < e.name.len) : (i += 1) {
            var c = e.name[i];
            if (c == '\\') {
                i += 1;
                if (i >= e.name.len) return error.BadLine;
                c = switch (e.name[i]) {
                    '\\' => '\\',
                    'n' => '\n',
                    else => return error.BadLine,
                };
            }
            if (n >= out.len) return error.ShortBuffer;
            out[n] = c;
            n += 1;
        }
        return out[0..n];
    }
};

const tags = [_]struct { tag: []const u8, algo: Algorithm }{
    .{ .tag = "SHA224", .algo = .sha224 },
    .{ .tag = "SHA256", .algo = .sha256 },
    .{ .tag = "SHA384", .algo = .sha384 },
    .{ .tag = "SHA512", .algo = .sha512 },
    .{ .tag = "SHA512/256", .algo = .sha512_256 },
    .{ .tag = "SHA3-256", .algo = .sha3_256 },
    .{ .tag = "SHA3-512", .algo = .sha3_512 },
    .{ .tag = "BLAKE2b-256", .algo = .blake2b256 },
    .{ .tag = "BLAKE3", .algo = .blake3 },
};

/// The checksum-file tag for `algo` (what `--tag` prints).
pub fn tagOf(algo: Algorithm) []const u8 {
    for (tags) |t| if (t.algo == algo) return t.tag;
    unreachable; // every Algorithm has a row (checked by a test)
}

fn isHex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

/// Line-by-line parser. `next` returns the next entry, null at the end, or an
/// error for a bad line; after an error the next call continues with the
/// following line.
pub const Iterator = struct {
    rest: []const u8,
    line_no: usize = 0,

    pub fn init(text: []const u8) Iterator {
        return .{ .rest = text };
    }

    pub fn next(it: *Iterator) ParseError!?Entry {
        while (it.rest.len != 0) {
            var line = it.rest;
            if (std.mem.findScalar(u8, it.rest, '\n')) |nl| {
                line = it.rest[0..nl];
                it.rest = it.rest[nl + 1 ..];
            } else {
                it.rest = it.rest[it.rest.len..];
            }
            it.line_no += 1;
            if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len == 0 or line[0] == '#') continue;
            return try parseLine(line, it.line_no);
        }
        return null;
    }
};

/// Parse one line (no newline). `line_no` is stored in the entry.
pub fn parseLine(line: []const u8, line_no: usize) ParseError!Entry {
    // A leading backslash marks an escaped name in both forms.
    const escaped = line.len != 0 and line[0] == '\\';
    const body = if (escaped) line[1..] else line;
    // BSD tag form: "TAG (name) = hex". Tried first: a GNU line cannot have a
    // space inside its leading hex run, so the two never collide.
    if (std.mem.find(u8, body, " (")) |sp| {
        const tag = body[0..sp];
        if (std.mem.findScalar(u8, tag, ' ') == null) {
            const rest = body[sp + 2 ..];
            const close = std.mem.findLast(u8, rest, ") = ") orelse return error.BadLine;
            const name = rest[0..close];
            const digest = rest[close + 4 ..];
            if (name.len == 0 or !isHex(digest)) return error.BadLine;
            for (tags) |t| if (std.mem.eql(u8, t.tag, tag))
                return .{ .algo = t.algo, .digest = digest, .name = name, .escaped = escaped, .binary = true, .line = line_no };
            return error.UnknownTag;
        }
    }
    // GNU form: ["\"] hex ' ' (' ' | '*') name
    const s = body;
    const hex_end = std.mem.findNone(u8, s, "0123456789abcdefABCDEF") orelse return error.BadLine;
    if (hex_end == 0 or s.len < hex_end + 3 or s[hex_end] != ' ') return error.BadLine;
    const mode = s[hex_end + 1];
    if (mode != ' ' and mode != '*') return error.BadLine;
    const name = s[hex_end + 2 ..];
    if (name.len == 0) return error.BadLine;
    return .{ .algo = null, .digest = s[0..hex_end], .name = name, .escaped = escaped, .binary = mode == '*', .line = line_no };
}

pub const Status = enum {
    /// File hashed and equals the digest.
    ok,
    /// File hashed and differs.
    mismatch,
    /// File could not be opened or read.
    unreadable,
};

pub const VerifyError = error{
    /// The digest's length does not match the algorithm, or the name has a bad escape.
    BadLine,
    NameTooLong,
};

/// Hash the file `entry` names (relative to `dir`) and compare it with the
/// digest on the line (hex case ignored). `default_algo` is used for GNU
/// lines; a BSD tag's algorithm wins. Like `hashFile`, no size or time limit.
pub fn verifyEntry(io: std.Io, dir: std.Io.Dir, default_algo: Algorithm, entry: Entry) VerifyError!Status {
    const algo = entry.algo orelse default_algo;
    if (entry.digest.len != root.hexLength(algo)) return error.BadLine;
    var name_buf: [max_name_len]u8 = undefined;
    const name = entry.unescapeName(&name_buf) catch |e| switch (e) {
        error.BadLine => return error.BadLine,
        error.ShortBuffer => return error.NameTooLong,
    };
    var out: [root.max_hex_len]u8 = undefined;
    _ = (root.hashFileIn(algo, io, dir, name, &out) catch unreachable) orelse return .unreadable; // out is max_hex_len
    const hex = out[0..root.hexLength(algo)];
    return if (std.ascii.eqlIgnoreCase(hex, entry.digest)) .ok else .mismatch;
}

pub const Summary = struct {
    ok: usize = 0,
    mismatch: usize = 0,
    unreadable: usize = 0,
    /// Lines that did not parse or whose digest/name were unusable.
    malformed: usize = 0,

    pub fn allOk(s: Summary) bool {
        return s.mismatch == 0 and s.unreadable == 0 and s.malformed == 0;
    }
};

/// `sha256sum -c`: verify every entry of `text` against files under `dir`.
pub fn verifyAll(io: std.Io, dir: std.Io.Dir, default_algo: Algorithm, text: []const u8) Summary {
    var s: Summary = .{};
    var it = Iterator.init(text);
    while (true) {
        const maybe = it.next() catch {
            s.malformed += 1;
            continue;
        };
        const e = maybe orelse break;
        const st = verifyEntry(io, dir, default_algo, e) catch {
            s.malformed += 1;
            continue;
        };
        switch (st) {
            .ok => s.ok += 1,
            .mismatch => s.mismatch += 1,
            .unreadable => s.unreadable += 1,
        }
    }
    return s;
}
