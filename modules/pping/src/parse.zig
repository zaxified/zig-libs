// SPDX-License-Identifier: MIT

//! parse — the TCP Timestamps option (RFC 7323 §3) parser. Purely mechanical
//! TLV walking; no algorithmic judgment calls, so unlike `match.zig` this is
//! fully real, not a Fable stub.
//!
//! TCP options are a byte stream of TLV-ish entries following the fixed
//! 20-byte TCP header, up to the header's Data Offset. Three encodings this
//! parser must handle (RFC 793 §3.1, RFC 7323 §3.2):
//!   - `kind = 0` (End of Option List): terminates the whole options list —
//!     no length byte follows.
//!   - `kind = 1` (No-Operation): a single byte, used for padding/alignment
//!     (e.g. so the 10-byte Timestamps option lands on a 4-byte boundary
//!     after 2 leading NOPs — `01 01 08 0A ...` is the textbook encoding a
//!     real stack emits). No length byte follows.
//!   - every other `kind`: followed by a `length` byte counting the WHOLE
//!     option (kind + length + value), then `length - 2` bytes of value.
//! The Timestamps option itself is `kind = 8`, `length = 10`, value = TSval
//! (4 bytes, network/big-endian) then TSecr (4 bytes, network/big-endian).
//!
//! Hostile-input contract: `tcp_options` is untrusted wire data (arbitrary
//! bytes, possibly truncated, possibly declaring a length that overruns the
//! buffer, possibly declaring `length < 2`). `parseTcpTimestamps` must never
//! read past `tcp_options.len` and must never panic — a malformed or
//! truncated options blob simply means the loop stops and (if a Timestamps
//! option was not fully found before that point) `null` is returned. See the
//! fuzz-style test at the bottom for the property this must hold.

const std = @import("std");

/// The value carried by a TCP Timestamps option (RFC 7323 §3.2).
pub const Timestamps = struct {
    tsval: u32,
    tsecr: u32,
};

/// Walk `tcp_options` (the raw bytes of a TCP segment's options area, i.e.
/// everything after the fixed 20-byte header up to `4 * DataOffset`) looking
/// for a well-formed Timestamps option (`kind = 8`, `length = 10`). Returns
/// its `tsval`/`tsecr` on the FIRST one found (a well-formed TCP segment
/// carries at most one), or `null` if none is present before the options
/// list ends (an explicit `kind = 0`, the buffer is exhausted, or a
/// malformed/truncated option is encountered first). Never reads out of
/// bounds — see the module doc's hostile-input contract.
pub fn parseTcpTimestamps(tcp_options: []const u8) ?Timestamps {
    var i: usize = 0;
    while (i < tcp_options.len) {
        const kind = tcp_options[i];
        switch (kind) {
            0 => return null, // End of Option List — nothing found
            1 => i += 1, // NOP — single byte, no length field
            else => {
                // Every other kind is followed by a length byte covering
                // (kind + length + value). Bail out (not panic) on anything
                // that would read past the buffer or declares a nonsensical
                // length.
                if (i + 1 >= tcp_options.len) return null; // no room for length byte
                const len = tcp_options[i + 1];
                if (len < 2) return null; // malformed: must cover at least kind+length
                if (i + len > tcp_options.len) return null; // declared length overruns buffer

                if (kind == 8 and len == 10) {
                    const tsval = std.mem.readInt(u32, tcp_options[i + 2 ..][0..4], .big);
                    const tsecr = std.mem.readInt(u32, tcp_options[i + 6 ..][0..4], .big);
                    return .{ .tsval = tsval, .tsecr = tsecr };
                }
                i += len;
            },
        }
    }
    return null; // buffer exhausted without an End marker or a match
}

// ── KAT tests: real option-byte blobs ───────────────────────────────────────

const testing = std.testing;

test "parseTcpTimestamps: bare Timestamps option, no padding" {
    // kind=8 len=10 tsval=0x00000001 tsecr=0x00000002
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 1), ts.tsval);
    try testing.expectEqual(@as(u32, 2), ts.tsecr);
}

test "parseTcpTimestamps: two leading NOPs before Timestamps (the textbook real-world encoding)" {
    // 01 01 08 0A <tsval=0x12345678> <tsecr=0x9abcdef0>
    const bytes = [_]u8{ 1, 1, 8, 10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 0x12345678), ts.tsval);
    try testing.expectEqual(@as(u32, 0x9abcdef0), ts.tsecr);
}

test "parseTcpTimestamps: MSS option before Timestamps is skipped correctly" {
    // kind=2 len=4 (MSS, 2 bytes value) then Timestamps.
    const bytes = [_]u8{ 2, 4, 0x05, 0xb4 } ++ [_]u8{ 8, 10, 0, 0, 0, 100, 0, 0, 0, 200 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 100), ts.tsval);
    try testing.expectEqual(@as(u32, 200), ts.tsecr);
}

test "parseTcpTimestamps: SACK-permitted (kind=4, len=2, no value bytes) then Timestamps" {
    const bytes = [_]u8{ 4, 2 } ++ [_]u8{ 8, 10, 0, 0, 0, 7, 0, 0, 0, 9 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 7), ts.tsval);
    try testing.expectEqual(@as(u32, 9), ts.tsecr);
}

test "parseTcpTimestamps: End-of-Option-List before any Timestamps option -> null" {
    const bytes = [_]u8{ 2, 4, 0x05, 0xb4, 0 }; // MSS, then END
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: no options at all -> null" {
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&.{}));
}

test "parseTcpTimestamps: options present but no Timestamps among them -> null" {
    const bytes = [_]u8{ 2, 4, 0x05, 0xb4, 4, 2, 1, 1 }; // MSS, SACK-permitted, NOP, NOP
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: only the FIRST well-formed Timestamps option is honored" {
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 } ++ [_]u8{ 8, 10, 0, 0, 0, 99, 0, 0, 0, 99 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 1), ts.tsval);
    try testing.expectEqual(@as(u32, 2), ts.tsecr);
}

// ── hostile-input KAT tests: truncated / malformed, must not read OOB ───────

test "parseTcpTimestamps: truncated right after a Timestamps kind byte -> null, no OOB" {
    const bytes = [_]u8{8};
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: kind+length present but value truncated -> null, no OOB" {
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 1 }; // declares len=10 but only 6 bytes follow kind
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: length byte declares less than 2 -> malformed, null, no OOB" {
    const bytes = [_]u8{ 8, 1, 0, 0 };
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: length byte declares less than 2 (zero) -> malformed, null, no OOB" {
    const bytes = [_]u8{ 8, 0 };
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: kind=8 but wrong length (not 10) is skipped as an opaque option, not matched" {
    // A hostile/broken kind=8 option claiming length=4 (too short to be a
    // real Timestamps option) must be skipped as opaque, not misread.
    const bytes = [_]u8{ 8, 4, 0xAA, 0xBB } ++ [_]u8{ 8, 10, 0, 0, 0, 5, 0, 0, 0, 6 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 5), ts.tsval);
    try testing.expectEqual(@as(u32, 6), ts.tsecr);
}

test "parseTcpTimestamps: length byte declares a value that exactly reaches the buffer end (boundary, no OOB)" {
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 0xFF, 0, 0, 0, 0xEE };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 0xFF), ts.tsval);
    try testing.expectEqual(@as(u32, 0xEE), ts.tsecr);
}

test "parseTcpTimestamps: length byte declares one past the buffer end -> null, no OOB" {
    const bytes = [_]u8{ 8, 11, 0, 0, 0, 0xFF, 0, 0, 0, 0xEE }; // len=11 but only 10 bytes present
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: all-NOP buffer -> null, no OOB" {
    const bytes = [_]u8{1} ** 40;
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

test "parseTcpTimestamps: huge declared length (255) on a short buffer -> null, no OOB" {
    const bytes = [_]u8{ 8, 255, 1, 2, 3 };
    try testing.expectEqual(@as(?Timestamps, null), parseTcpTimestamps(&bytes));
}

// ── real-capture goldens (loopback TCP handshake, tcpdump, 2026-08-01) ─────
//
// Every fixture above this point is a hand-built options blob — plausible,
// but never checked against what a real TCP stack actually puts on the
// wire. These two are the raw TCP options bytes from a genuine SYN and
// SYN-ACK of one real loopback TCP connection (a Python client/server),
// captured with `tcpdump -i lo` inside a throwaway, unprivileged
// `unshare --user --net` namespace (CAP_NET_RAW exists only inside that
// disposable namespace — no host capability change, no setcap, nothing
// persistent). They anchor the option *ordering* a real stack actually
// uses (MSS, SACK-permitted, Timestamps, NOP, Window-scale — not the
// bare-option or single-other-option shapes every hand-built fixture above
// picks) and a real, correlated tsval/tsecr pair (the SYN-ACK's tsecr
// really is the SYN's tsval — an RTT-computation input, not just a parser
// input).
const syn_tcp_options = [_]u8{
    0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0xbd, 0x38, 0x76, 0xfd, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x03, 0x0a,
};
const synack_tcp_options = [_]u8{
    0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x0a, 0xb3, 0xb7, 0xd4, 0xbd, 0x38, 0x76, 0xfd,
    0x01, 0x03, 0x03, 0x0a,
};

test "golden: real capture — SYN options from a genuine loopback TCP handshake" {
    // options: [mss 65495, sackOK, TS val 3174594301 ecr 0, nop, wscale 10]
    const ts = parseTcpTimestamps(&syn_tcp_options).?;
    try testing.expectEqual(@as(u32, 3174594301), ts.tsval);
    try testing.expectEqual(@as(u32, 0), ts.tsecr);
}

test "golden: real capture — SYN-ACK options echo the SYN's tsval as tsecr" {
    // options: [mss 65495, sackOK, TS val 179550164 ecr 3174594301, nop, wscale 10]
    const ts = parseTcpTimestamps(&synack_tcp_options).?;
    try testing.expectEqual(@as(u32, 179550164), ts.tsval);
    // The real, kernel-computed correlation this module's whole RTT
    // computation depends on: the peer's tsecr genuinely is our tsval.
    const syn_ts = parseTcpTimestamps(&syn_tcp_options).?;
    try testing.expectEqual(syn_ts.tsval, ts.tsecr);
}

test "golden: real-capture fixture count + size canary — 2 real loopback captures" {
    try testing.expectEqual(@as(usize, 20), syn_tcp_options.len);
    try testing.expectEqual(@as(usize, 20), synack_tcp_options.len);
}

// ── fuzz-style: hostile random input never reads out of bounds / never panics ──

/// Deterministic 64-bit LCG (Knuth MMIX constants), same construction
/// `latency-stats` uses for reproducible fuzz-style corpora — no dependency
/// on `std.crypto.random` (removed in 0.16) or any other RNG module.
fn lcg(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.* >> 11;
}

test "parseTcpTimestamps: fuzz — hostile random buffers of every length never panic or read OOB" {
    var state: u64 = 0xD1B54A32D192ED03;
    var buf: [64]u8 = undefined;
    var trial: usize = 0;
    while (trial < 20_000) : (trial += 1) {
        const len: usize = @intCast(lcg(&state) % (buf.len + 1));
        for (buf[0..len]) |*b| b.* = @truncate(lcg(&state));
        // Under Zig's safety-checked builds (Debug/ReleaseSafe), any
        // out-of-bounds slice access panics the process — so simply calling
        // this on thousands of adversarial buffers without a panic IS the
        // property under test. The return value is unconstrained (any
        // Timestamps or null is a legal outcome of random bytes); only "did
        // it crash / read OOB" matters here.
        const result = parseTcpTimestamps(buf[0..len]);
        _ = result;
    }
}

test "parseTcpTimestamps: fuzz — a genuine Timestamps option embedded in random padding is still found and never crashes" {
    var state: u64 = 0x9E3779B97F4A7C15;
    var buf: [64]u8 = undefined;
    var trial: usize = 0;
    while (trial < 5_000) : (trial += 1) {
        const prefix_len: usize = @intCast(lcg(&state) % 20);
        for (buf[0..prefix_len]) |*b| b.* = 1; // valid NOP padding, never misparsed
        const tsval: u32 = @truncate(lcg(&state));
        const tsecr: u32 = @truncate(lcg(&state));
        buf[prefix_len] = 8;
        buf[prefix_len + 1] = 10;
        std.mem.writeInt(u32, buf[prefix_len + 2 ..][0..4], tsval, .big);
        std.mem.writeInt(u32, buf[prefix_len + 6 ..][0..4], tsecr, .big);
        const total_len = prefix_len + 10;
        const ts = parseTcpTimestamps(buf[0..total_len]).?;
        try testing.expectEqual(tsval, ts.tsval);
        try testing.expectEqual(tsecr, ts.tsecr);
    }
}

// ── check-fuzz coverage: a real `testing.fuzz` harness ──────────────────────
//
// The two tests above predate `zig build check-fuzz` and already cover the
// "never panics / never reads OOB" property with 25,000 deterministic LCG
// trials — genuinely fuzz-STYLE, just not built on `std.testing.Smith`, so
// the gate (which greps for `testing.fuzz(`) cannot see them and neither can
// `--fuzz`'s coverage-guided corpus growth. This harness is the gate-visible
// form, TLV-shaped so it spends most of its budget on well-formed-ish option
// sequences (kind/length pairs, NOPs, END, an occasional genuine Timestamps
// option) rather than the "rejected at the first kind byte" case pure random
// bytes would mostly produce.
test "fuzz: parseTcpTimestamps never panics or reads OOB, arbitrary or TLV-shaped bytes" {
    try std.testing.fuzz({}, fuzzParseNeverPanics, .{ .corpus = &fuzz_corpus });
}

const fuzz_corpus = [_][]const u8{
    &syn_tcp_options,
    &synack_tcp_options,
};

fn fuzzParseNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    const opts = buildTcpOptions(smith, &buf);
    _ = parseTcpTimestamps(opts);
}

/// One draw in six is pure arbitrary bytes; the rest assemble a sequence of
/// TLV-ish entries: END (stops the list), NOP (single byte), a genuine
/// `kind=8 len=10` Timestamps option with random TSval/TSecr, or an opaque
/// option with an arbitrary (possibly malformed — too short, overrunning the
/// buffer) length byte.
fn buildTcpOptions(smith: *std.testing.Smith, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 5) == 0) {
        smith.bytes(buf);
        const len = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
        return buf[0..len];
    }
    var pos: usize = 0;
    const n_entries = smith.valueRangeAtMost(u8, 0, 8);
    var i: u8 = 0;
    while (i < n_entries and pos < buf.len) : (i += 1) {
        switch (smith.valueRangeAtMost(u8, 0, 4)) {
            0 => {
                buf[pos] = 0; // End of Option List
                pos += 1;
                break;
            },
            1 => {
                buf[pos] = 1; // NOP
                pos += 1;
            },
            2 => {
                if (pos + 10 > buf.len) break;
                buf[pos] = 8;
                buf[pos + 1] = 10;
                smith.bytes(buf[pos + 2 .. pos + 10]);
                pos += 10;
            },
            else => {
                if (pos + 1 >= buf.len) break;
                buf[pos] = smith.value(u8); // kind
                const len = smith.value(u8); // possibly malformed length
                buf[pos + 1] = len;
                pos += 2;
                const value_len = @min(@as(usize, if (len >= 2) len - 2 else 0), buf.len - pos);
                if (value_len > 0) {
                    smith.bytes(buf[pos..][0..value_len]);
                    pos += value_len;
                }
            },
        }
    }
    return buf[0..pos];
}
