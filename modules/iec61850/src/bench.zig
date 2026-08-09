// SPDX-License-Identifier: MIT
//! Opt-in profile of the F4 finding: `report.Report.decode`/
//! `decodeInformationReport` used to return the 9,344-byte `Report` struct
//! **by value**, so every inbound report cost a full struct copy on top of
//! the decode itself. Fixed by an out-parameter (`report.zig`'s `Report.decode`
//! doc comment, "partial-failure contract"). Off by default
//! (`error.SkipZigTest`); run it with:
//!
//!   IEC61850_BENCH=1 scripts/capped zig build test-iec61850 -Doptimize=ReleaseFast
//!
//! **Sizing.** One 106-octet captured `InformationReport`, decoded in a loop —
//! nothing close to the memory an over-eager benchmark has OOM-killed this
//! host with before. Run under `scripts/capped`.

const std = @import("std");
const report = @import("report.zig");
const mms = @import("mms.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// The same captured `InformationReport` `report.zig`'s own tests decode
/// (`captured_report`, first report after a general interrogation of
/// `LLN0$Events`) — a realistic wire size (106 octets, 4 data-set entries),
/// not a synthetic worst case.
const captured_report = [_]u8{
    0xA3, 0x66, 0xA0, 0x64,
    0xA1, 0x05, 0x80, 0x03,
    'R',  'P',  'T',  0xA0,
    0x5B, 0x8A, 0x07, 'E',
    'v',  'e',  'n',  't',
    's',  '1',  0x84, 0x03,
    0x06, 0x78, 0x80, 0x86,
    0x01, 0x00, 0x8C, 0x06,
    0x01, 0xE9, 0xC1, 0x11,
    0x3C, 0xB8, 0x8A, 0x1D,
    's',  'i',  'm',  'p',
    'l',  'e',  'I',  'O',
    'G',  'e',  'n',  'e',
    'r',  'i',  'c',  'I',
    'O',  '/',  'L',  'L',
    'N',  '0',  '$',  'E',
    'v',  'e',  'n',  't',
    's',  0x86, 0x01, 0x01,
    0x84, 0x02, 0x04, 0xF0,
    0x83, 0x01, 0x00, 0x83,
    0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
};

test "bench (opt-in via IEC61850_BENCH): F4 report decode cost, by-value vs out-param" {
    if (std.testing.environ.getPosix("IEC61850_BENCH") == null) return error.SkipZigTest;

    const iters: usize = 200_000;

    std.debug.print("\niec61850: F4 report decode cost (@sizeOf(report.Report) = {d})\n", .{@sizeOf(report.Report)});

    // Caller-owned storage, reused across every call — the out-param contract.
    var r: report.Report = undefined;
    const t0 = nowNs();
    for (0..iters) |_| {
        const pdu = mms.decode(&captured_report) catch unreachable;
        report.decodeInformationReport(&r, pdu.unconfirmed.body) catch unreachable;
        std.mem.doNotOptimizeAway(r.entry_count);
    }
    const ns = (nowNs() - t0) / iters;
    std.debug.print("  decodeInformationReport(&r, body): {d} ns/call\n", .{ns});
    std.debug.print(
        "  (pre-fix this signature was `body: []const u8) Error!Report`, returning\n" ++
            "  the 9,344-byte struct by value; compare against the before-number\n" ++
            "  captured in the F4 disposition row)\n",
        .{},
    );
}
