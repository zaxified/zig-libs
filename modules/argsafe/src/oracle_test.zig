// SPDX-License-Identifier: MIT
//! Replay of the foreign verdicts frozen in `oracle_vectors.zig` (taken by
//! `tools/oracle.py gen`: POSIX sh via Python shlex + dash, the UCRT command-line rules,
//! go-playground/validator v10.30.5, the Linux kernel's interface-name check).
//!
//! Every disagreement carries a label: `agree` (same verdict), `reject` (we refuse what
//! the foreign side takes: we are stricter on purpose, each case class named and checked),
//! `ours` (we accept what the foreign side refuses: must be none for the one-word
//! predicates, because that is the security direction).
const std = @import("std");
const testing = std.testing;
const argsafe = @import("root.zig");
const v = @import("oracle_vectors.zig");

const SHELL = 1;
const WIN = 2;
const GOHOST = 4;
const GOPORT = 8;
const KERNEL = 16;

fn decode(buf: []u8, h: []const u8) []const u8 {
    return std.fmt.hexToBytes(buf[0 .. h.len / 2], h) catch unreachable;
}

fn isIdent(s: []const u8) bool {
    return argsafe.isSafeIdentifier(s);
}
fn isB64(s: []const u8) bool {
    return argsafe.isSafeBase64(s, null);
}
fn isCidr(s: []const u8) bool {
    return argsafe.isSafeCidrList(s, ',');
}
fn isKvToken(s: []const u8) bool {
    return argsafe.isSafeKvValue(s, false);
}
fn isKvPrintable(s: []const u8) bool {
    return argsafe.isSafeKvValue(s, true);
}

/// Predicates whose accepted strings are claimed to be ONE literal word to a POSIX shell
/// and to CommandLineToArgvW, as a side effect of their character classes. (`isSafePath`,
/// `isSafeUrl` and the printable `isSafeKvValue` are argv-only by design and are not here.)
const one_word = [_]struct { name: []const u8, f: *const fn ([]const u8) bool }{
    .{ .name = "identifier", .f = isIdent },
    .{ .name = "base64", .f = isB64 },
    .{ .name = "cidr-list", .f = isCidr },
    .{ .name = "kv-token", .f = isKvToken },
    .{ .name = "hostname", .f = argsafe.isSafeHostname },
    .{ .name = "port", .f = argsafe.isSafePort },
    .{ .name = "ifname", .f = argsafe.isSafeIfname },
};

test "oracle: every string a one-word predicate accepts is one word to POSIX sh and to CommandLineToArgvW" {
    var counts: [one_word.len]usize = @splat(0);
    var buf: [4096]u8 = undefined;
    for (v.vectors) |vec| {
        const s = decode(&buf, vec.h);
        inline for (one_word, 0..) |p, i| {
            if (p.f(s)) {
                counts[i] += 1;
                testing.expect(vec.f & SHELL != 0 and vec.f & WIN != 0) catch |e| {
                    std.debug.print("{s} accepts {x}: sh={} win={}\n", .{ p.name, s, vec.f & SHELL != 0, vec.f & WIN != 0 });
                    return e;
                };
            }
        }
    }
    // reach: the corpus must put real accepted strings through each predicate
    inline for (one_word, 0..) |p, i| {
        testing.expect(counts[i] >= 30) catch |e| {
            std.debug.print("{s}: only {d} accepted vectors\n", .{ p.name, counts[i] });
            return e;
        };
    }
}

test "oracle: the argv-only predicates are NOT shell-safe, by design (label: ours)" {
    var path_unsafe: usize = 0;
    var url_unsafe: usize = 0;
    var kv_unsafe: usize = 0;
    var buf: [4096]u8 = undefined;
    for (v.vectors) |vec| {
        const s = decode(&buf, vec.h);
        if (argsafe.isSafePath(s) and vec.f & SHELL == 0) path_unsafe += 1;
        if (argsafe.isSafeUrl(s) and vec.f & SHELL == 0) url_unsafe += 1;
        if (isKvPrintable(s) and vec.f & SHELL == 0) kv_unsafe += 1;
    }
    // If one of these ever drops to zero the corpus lost its reach; if the predicate were
    // made shell-safe the docs ("argv only, never a shell") must change with it.
    try testing.expect(path_unsafe > 0);
    try testing.expect(url_unsafe > 0);
    try testing.expect(kv_unsafe > 0);
}

fn hostLabelsEndInDash(s: []const u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |l| if (l.len > 0 and l[l.len - 1] == '-') return true;
    return false;
}

test "oracle: hostname against go-playground hostname_rfc1123 (agree / reject / ours)" {
    var agree: usize = 0;
    var reject: usize = 0;
    var buf: [4096]u8 = undefined;
    for (v.vectors) |vec| {
        const s = decode(&buf, vec.h);
        const ours = argsafe.isSafeHostname(s);
        const go = vec.f & GOHOST != 0;
        if (ours == go) {
            agree += 1;
        } else if (!ours and go) {
            // label `reject`: Go lets a label end in '-' and puts no cap on the total length
            reject += 1;
            testing.expect(hostLabelsEndInDash(s) or s.len > 253) catch |e| {
                std.debug.print("unexplained reject: {x}\n", .{s});
                return e;
            };
        } else {
            std.debug.print("label ours: we accept {x}, go refuses\n", .{s});
            return error.OursAcceptsForeignRefuses;
        }
    }
    try testing.expect(agree > 1000 and reject > 0);
}

test "oracle: port against go-playground hostname_port's port half (agree / reject / ours)" {
    var agree: usize = 0;
    var reject: usize = 0;
    var buf: [4096]u8 = undefined;
    for (v.vectors) |vec| {
        const s = decode(&buf, vec.h);
        const ours = argsafe.isSafePort(s);
        const go = vec.f & GOPORT != 0;
        if (ours == go) {
            agree += 1;
        } else if (!ours and go) {
            // label `reject`: Go's ParseInt takes "+80" and "00080"; we want one spelling
            reject += 1;
            testing.expect(s.len > 1 and (s[0] == '+' or s[0] == '0')) catch |e| {
                std.debug.print("unexplained reject: {x}\n", .{s});
                return e;
            };
        } else {
            std.debug.print("label ours: we accept {x}, go refuses\n", .{s});
            return error.OursAcceptsForeignRefuses;
        }
    }
    try testing.expect(agree > 1000 and reject > 0);
}

test "oracle: interface name against the kernel's rename check (agree / reject / ours)" {
    var agree: usize = 0;
    var reject: usize = 0;
    var buf: [4096]u8 = undefined;
    for (v.vectors) |vec| {
        const s = decode(&buf, vec.h);
        const ours = argsafe.isSafeIfname(s);
        const kernel = vec.f & KERNEL != 0;
        if (ours == kernel) {
            agree += 1;
        } else if (!ours and kernel) {
            reject += 1; // we are a strict subset: the kernel takes far more bytes
        } else {
            std.debug.print("label ours: we accept {x}, the kernel refuses\n", .{s});
            return error.OursAcceptsForeignRefuses;
        }
    }
    try testing.expect(agree > 1000 and reject > 100);
}
