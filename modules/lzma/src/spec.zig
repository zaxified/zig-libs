// SPDX-License-Identifier: MIT

//! The little option-string language the differential tests and goldens use
//! to name an encoder configuration: a preset (`6`, `9e`) and overrides
//! (`6,dict=65536,lc=0,lp=2,pb=1,mode=fast,nice=32,mf=hc4,depth=5`), the same
//! spelling `tools/c_oracle/lzref.c` takes. Public only for the tools.

const std = @import("std");
const enc = @import("encoder.zig");

pub fn parse(spec: []const u8) !enc.LzmaOptions {
    var it = std.mem.splitScalar(u8, spec, ',');
    const first = it.next().?;
    const extreme = first[first.len - 1] == 'e';
    const level = try std.fmt.parseInt(u4, if (extreme) first[0 .. first.len - 1] else first, 10);
    var o = enc.preset(level, extreme);
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadSpec;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "dict")) {
            o.dict_size = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "lc")) {
            o.lc = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "lp")) {
            o.lp = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "pb")) {
            o.pb = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "nice")) {
            o.nice_len = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "depth")) {
            o.depth = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "mode")) {
            o.mode = if (std.mem.eql(u8, v, "fast")) .fast else .normal;
        } else if (std.mem.eql(u8, k, "mf")) {
            o.mf = if (std.mem.eql(u8, v, "hc3")) .hc3 else if (std.mem.eql(u8, v, "hc4")) .hc4 else if (std.mem.eql(u8, v, "bt2")) .bt2 else if (std.mem.eql(u8, v, "bt3")) .bt3 else .bt4;
        } else return error.BadSpec;
    }
    return o;
}

pub fn checkOf(name: []const u8) enc.Check {
    if (std.mem.eql(u8, name, "none")) return .none;
    if (std.mem.eql(u8, name, "crc32")) return .crc32;
    if (std.mem.eql(u8, name, "sha256")) return .sha256;
    return .crc64;
}

pub fn formatOf(name: []const u8) enc.Format {
    if (std.mem.eql(u8, name, "xz")) return .xz;
    if (std.mem.eql(u8, name, "alone")) return .lzma_alone;
    if (std.mem.eql(u8, name, "raw1")) return .lzma1;
    return .lzma2;
}
