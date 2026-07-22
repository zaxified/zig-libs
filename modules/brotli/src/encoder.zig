//! Minimal, correct Brotli encoder (RFC 7932).
//!
//! Emits a valid `Content-Encoding: br` stream built from uncompressed
//! meta-blocks (ISUNCOMPRESSED=1) followed by an empty final meta-block. The
//! output is a fully RFC-7932-conformant stream that any compliant decoder
//! (this module's decoder and the reference `brotli`) accepts. It performs NO
//! LZ77 / entropy coding, so the ratio is ~1.0 (a few bytes of framing
//! overhead per 16 MiB block). A real compressing encoder is future work; see
//! SPEC.md. Store mode is nonetheless a legitimate, interoperable v1 for
//! transport that just needs a valid `br` body.

const std = @import("std");

/// Maximum bytes per uncompressed meta-block (MLEN is a 24-bit field + 1).
const max_block = 1 << 24;

const BitWriter = struct {
    buf: std.ArrayListUnmanaged(u8) = .empty,
    acc: u64 = 0,
    cnt: u6 = 0,
    gpa: std.mem.Allocator,

    fn writeBits(self: *BitWriter, val: u32, n: u6) std.mem.Allocator.Error!void {
        const m: u64 = (@as(u64, 1) << n) - 1;
        self.acc |= (@as(u64, val) & m) << self.cnt;
        self.cnt += n;
        while (self.cnt >= 8) {
            try self.buf.append(self.gpa, @truncate(self.acc & 0xff));
            self.acc >>= 8;
            self.cnt -= 8;
        }
    }

    fn alignToByte(self: *BitWriter) std.mem.Allocator.Error!void {
        if (self.cnt != 0) {
            try self.buf.append(self.gpa, @truncate(self.acc & 0xff));
            self.acc = 0;
            self.cnt = 0;
        }
    }

    fn writeBytes(self: *BitWriter, bytes: []const u8) std.mem.Allocator.Error!void {
        try self.buf.appendSlice(self.gpa, bytes);
    }
};

/// Compress `input` into a valid Brotli stream (store mode; see file docs).
/// Caller owns the returned slice.
pub fn compress(gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error![]u8 {
    var w = BitWriter{ .gpa = gpa };
    errdefer w.buf.deinit(gpa);

    // WBITS = 16 (single 0 bit) — window is irrelevant for stored blocks.
    try w.writeBits(0, 1);

    var off: usize = 0;
    while (off < input.len) {
        const remaining = input.len - off;
        const n = @min(remaining, max_block);
        // Non-last, uncompressed meta-block.
        try w.writeBits(0, 1); // ISLAST = 0
        // MNIBBLES: pick the smallest nibble count that holds (n-1).
        const mlen_minus_1: u32 = @intCast(n - 1);
        var size_nibbles: u6 = 4;
        if (mlen_minus_1 >= (1 << 20)) {
            size_nibbles = 6;
        } else if (mlen_minus_1 >= (1 << 16)) {
            size_nibbles = 5;
        }
        try w.writeBits(size_nibbles - 4, 2); // MNIBBLES selector (0,1,2)
        try w.writeBits(mlen_minus_1, size_nibbles * 4);
        try w.writeBits(1, 1); // ISUNCOMPRESSED = 1
        try w.alignToByte();
        try w.writeBytes(input[off..][0..n]);
        off += n;
    }

    // Final empty meta-block: ISLAST = 1, ISLASTEMPTY = 1.
    try w.writeBits(1, 1);
    try w.writeBits(1, 1);
    try w.alignToByte();

    return w.buf.toOwnedSlice(gpa);
}
