#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""protobuf mutation runner — every guard removed AND weakened, 32 in all.

WHY THIS EXISTS. This module's suite is large and green. That is a statement
about the code, not about the suite: a bound, a UTF-8 check or a depth cap can be
deleted and every test can still pass. This breaks each one on purpose, in its
own copy of the module with its own `--cache-dir`, and records whether the suite
noticed. `PC1`/`PC2` are POSITIVE CONTROLS (zigzag and the varint mask); if
either SURVIVES, the runner is broken and no other row means anything.

⚠ ONE CACHE DIR PER MUTATION IS LOAD-BEARING. A shared cache once served a stale
binary in this campaign and produced 18 false PASSes.

⚠ IT MUTATES A COPY, NEVER THE TRACKED TREE. The copy is taken from `../src` at
run time — deliberately, because the audit's own base tree had drifted: by
2026-09-16 it was 339 lines behind `decode.zig`, 320 behind `encode.zig`, still
carried `reference_interop.zig` and lacked `conformance.zig`. A mutation runner
pointed at a stale snapshot reports on code that no longer exists, which is worse
than no report.

⚠ SIX ANCHORS ARE KNOWN TO BE STALE against the current sources: V1–V4
(`wire.zig`, the varint cap and the 10th-byte checks) and D3/D4 (`encode.zig`,
the encoder depth caps). They will report PATCH-FAILED, which is the honest
outcome — a patch that did not land is a MISSING ROW, never a verdict. Fixing
them means re-reading those functions and re-deriving the edit, not loosening the
match.

WHAT IT NEEDS. A `zig` on PATH. Nothing else.

    python3 mutate.py            # all 32
    python3 mutate.py L1 U2      # only these

WHAT IT PRODUCES. One line per mutation — KILLED, SURVIVED, PATCH-FAILED or
compile-error — and a non-zero exit if a positive control was not killed.
"""
import os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SRC = os.path.join(HERE, "..", "src")
TESTKIT = os.path.join(ROOT, "modules", "testkit")
WORK = os.path.join(ROOT, ".zig-cache", "protobuf-mutate")

# (id, file, old, new, note)
MUTS = [
    # ── POSITIVE CONTROLS: must be RED, or the runner is broken ──────────────
    ("PC1", "wire.zig", "pub fn zigzagEncode(value: i64) u64 {\n    return @bitCast((value << 1) ^ (value >> 63));",
     "pub fn zigzagEncode(value: i64) u64 {\n    return @bitCast((value << 1) ^ (value >> 62));", "positive control: zigzag broken"),
    ("PC2", "wire.zig", "        result |= @as(u64, b & 0x7f) << shift;",
     "        result |= @as(u64, b & 0x3f) << shift;", "positive control: varint mask broken"),

    # ── the length bound ─────────────────────────────────────────────────────
    ("L1", "wire.zig", "        if (n > @as(u64, self.remaining())) return error.Truncated;",
     "        if (n > @as(u64, self.remaining()) and false) return error.Truncated;", "DELETE the length bound"),
    ("L2", "wire.zig", "        if (n > @as(u64, self.remaining())) return error.Truncated;",
     "        if (n > @as(u64, self.remaining()) + 1) return error.Truncated;", "WEAKEN length bound by 1"),
    ("L3", "wire.zig", "        if (n > @as(u64, self.remaining())) return error.Truncated;",
     "        if (n > @as(u64, self.remaining()) +| 64) return error.Truncated;", "WEAKEN length bound by 64"),
    ("L4", "wire.zig", "        if (n > @as(u64, self.remaining())) return error.Truncated;",
     "        if (n > @as(u64, self.remaining()) and n < (1 << 40)) return error.Truncated;",
     "WEAKEN: only lengths below 2^40 are bounded"),

    # ── varint discipline ──────────────── (V1–V4: stale anchors, see header) ─
    ("V1", "wire.zig", "        for (0..10) |i| {", "        for (0..11) |i| {", "WEAKEN varint cap 10 -> 11"),
    ("V2", "wire.zig", "                if (b > 1) return error.VarintOverflow;",
     "                if (b > 3) return error.VarintOverflow;", "WEAKEN 10th-byte bit check"),
    ("V3", "wire.zig", "                if (b > 1) return error.VarintOverflow;",
     "                if (b > 255) return error.VarintOverflow;", "DELETE 10th-byte bit check"),
    ("V4", "wire.zig", "        return error.VarintOverflow;\n    }\n\n    pub fn fixed32",
     "        return result;\n    }\n\n    pub fn fixed32", "DELETE over-long varint rejection"),

    # ── tag validation ───────────────────────────────────────────────────────
    ("T1", "wire.zig", "        if (number == 0) return error.FieldNumberZero;",
     "        if (number == 0 and number == 1) return error.FieldNumberZero;", "DELETE field-0 rejection"),
    ("T2", "wire.zig", "        if (number > std.math.maxInt(u29)) return error.FieldNumberOutOfRange;",
     "        if (number > std.math.maxInt(u32)) return error.FieldNumberOutOfRange;", "WEAKEN field-number ceiling to 2^32"),
    ("T3", "wire.zig", "            .sgroup, .egroup => return error.UnsupportedWireType,",
     "            .sgroup, .egroup => {},", "DELETE group rejection"),
    ("T4", "wire.zig", "            _ => return error.UnsupportedWireType,",
     "            _ => {},", "DELETE unassigned-wire-type rejection"),

    # ── depth cap ──────────────────────── (D3/D4: stale anchors, see header) ─
    ("D1", "decode.zig", "    if (depth >= options.max_depth) return error.DepthExceeded;",
     "    if (depth >= @as(u16, options.max_depth) * 4) return error.DepthExceeded;", "WEAKEN decode depth cap x4"),
    ("D2", "decode.zig", "    if (depth >= options.max_depth) return error.DepthExceeded;",
     "    if (depth > options.max_depth) return error.DepthExceeded;", "WEAKEN decode depth cap by 1"),
    ("D3", "encode.zig", "fn messageSize(comptime T: type, value: T, options: Options, depth: u8) Error!usize {\n    if (depth >= options.max_depth) return error.DepthExceeded;",
     "fn messageSize(comptime T: type, value: T, options: Options, depth: u8) Error!usize {\n    if (depth >= 255) return error.DepthExceeded;", "DELETE encoder sizing depth cap"),
    ("D4", "encode.zig", "fn emitMessage(comptime T: type, value: T, e: *wire.Emitter, options: Options, depth: u8) Error!void {\n    if (depth >= options.max_depth) return error.DepthExceeded;",
     "fn emitMessage(comptime T: type, value: T, e: *wire.Emitter, options: Options, depth: u8) Error!void {\n    if (depth >= 255) return error.DepthExceeded;", "DELETE encoder emit depth cap"),

    # ── UTF-8 ────────────────────────────────────────────────────────────────
    ("U1", "decode.zig", "            if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;",
     "            if (!std.unicode.utf8ValidateSlice(raw) and raw.len > (1 << 40)) return error.InvalidUtf8;", "DELETE UTF-8 validation"),
    ("U2", "decode.zig", "            if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;",
     "            if (!std.unicode.utf8ValidateSlice(raw[0..@min(raw.len, 1)])) return error.InvalidUtf8;",
     "WEAKEN UTF-8 validation to the first byte"),
    ("U3", "decode.zig", "            if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;",
     "            if (raw.len < 64 and !std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;",
     "WEAKEN UTF-8 validation to strings under 64 bytes"),

    # ── merge semantics (the wave-2 F1 fix) ──────────────────────────────────
    ("M1", "decode.zig", "            0 => self.one = payload,", "            0 => self.one = payload,\n            // mutated",
     "no-op sanity (must stay GREEN)"),
    ("M2", "decode.zig", "    fn bytes(self: MergeBuf) ?[]const u8 {\n        return switch (self.count) {\n            0 => null,\n            1 => self.one,\n            else => self.joined.items,",
     "    fn bytes(self: MergeBuf) ?[]const u8 {\n        return switch (self.count) {\n            0 => null,\n            1 => self.one,\n            else => self.joined.items[self.joined.items.len - self.one.len ..],",
     "WEAKEN merge: keep only the LAST occurrence (replace, not merge)"),

    # ── enum / unknown-field policy ──────────────────────────────────────────
    ("E1", "decode.zig", "                break :blk std.enums.fromInt(E, raw) orelse return error.InvalidEnumValue;",
     "                break :blk std.enums.fromInt(E, raw) orelse @as(E, @enumFromInt(0));",
     "WEAKEN exhaustive-enum rejection to a silent default"),
    ("K1", "decode.zig", "            if (options.reject_unknown_fields) return error.UnknownField;",
     "            if (options.reject_unknown_fields and tag.number == 0) return error.UnknownField;", "DELETE reject_unknown_fields"),
    ("K2", "decode.zig", "            if (comptime unknownFieldName(T)) |name|\n                try @field(lists, name).appendSlice(arena, cur.buf[tag_start..cur.pos]);",
     "            if (comptime unknownFieldName(T)) |name|\n                try @field(lists, name).appendSlice(arena, cur.buf[tag_start..cur.pos][0..0]);",
     "WEAKEN unknown-field capture to zero bytes"),

    # ── packed / wire-type acceptance ────────────────────────────────────────
    ("P1", "decode.zig", "    return info.card == .repeated and info.kind.packable() and w == .len;",
     "    return true;", "WEAKEN accepts(): any wire type matches any field"),
    ("P2", "decode.zig", "    return info.card == .repeated and info.kind.packable() and w == .len;",
     "    return false;", "DELETE packed acceptance for repeated fields"),
    ("P3", "decode.zig", "                var sub = Cursor.init(try cur.take(n));",
     "                var sub = Cursor.init(cur.buf[cur.pos..]);", "WEAKEN packed payload bound to rest-of-buffer"),

    # ── encoder correctness ──────────────────────────────────────────────────
    ("N1", "encode.zig", "        .int32 => wire.signExtend(@as(i64, elem)),",
     "        .int32 => @as(u64, @as(u32, @bitCast(elem))),", "DELETE int32 sign extension (5-byte negative)"),
    ("N2", "encode.zig", "        .string, .bytes => elem.len == 0,",
     "        .string, .bytes => elem.len <= 1,", "WEAKEN isDefault: 1-byte strings dropped"),
    ("N3", "encode.zig", "    total += unknownOf(T, value).raw.len;", "    total += 0;",
     "size/emit disagreement: unknown bytes sized as 0"),
]


def run_one(mid, fname, old, new, note):
    d = os.path.join(WORK, "m_" + mid)
    if os.path.exists(d):
        shutil.rmtree(d)
    shutil.copytree(SRC, os.path.join(d, "src"))
    p = os.path.join(d, "src", fname)
    s = open(p).read()
    if s.count(old) != 1:
        return (mid, "PATCH-FAILED(%d hits)" % s.count(old), note, 0)
    open(p, "w").write(s.replace(old, new))
    cache = os.path.join(d, "zc")
    t0 = time.time()
    r = subprocess.run(["zig", "test", "--cache-dir", cache, "--dep", "testkit",
                        "-Mroot=" + os.path.join(d, "src", "root.zig"),
                        "-Mtestkit=" + os.path.join(TESTKIT, "src", "root.zig")],
                       capture_output=True, cwd=WORK, timeout=900)
    dt = time.time() - t0
    outp = (r.stdout + r.stderr).decode(errors="replace")
    # ⚠ Match the COUNT, never pin it. This read `"All 69 tests passed" in outp`
    # until 2026-09-16; the day the suite gained a 70th test, a green run would
    # have dropped into the `SURVIVED(?)` branch and, in the sibling runner that
    # lacked that branch, into KILLED -- a mutation reported as caught when it
    # had in fact survived.
    import re
    m_pass = re.search(r"All (\d+) tests passed", outp)
    if r.returncode == 0 and m_pass:
        verdict = "SURVIVED (%s/%s green)" % (m_pass.group(1), m_pass.group(1))
    elif r.returncode == 0:
        verdict = "SURVIVED(?) rc=0"
    elif "error:" in outp and "tests passed" not in outp and "FAIL" not in outp:
        first = next((l for l in outp.splitlines() if "error:" in l), "")
        verdict = "compile-error: " + first.strip()[:80]
    else:
        fails = [l for l in outp.splitlines() if "FAIL" in l or "panic" in l or "error: " in l]
        verdict = "KILLED: " + (fails[0].strip()[:110] if fails else "rc=%d" % r.returncode)
    shutil.rmtree(d, ignore_errors=True)
    return (mid, verdict, note, dt)


if __name__ == "__main__":
    os.makedirs(WORK, exist_ok=True)
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    rows = []
    for (mid, f, old, new, note) in MUTS:
        if only and mid not in only:
            continue
        r = run_one(mid, f, old, new, note)
        rows.append(r)
        print("%-5s %-58s %-52s %.0fs" % (r[0], r[2], r[1], r[3]), flush=True)
    bad = [r for r in rows if r[0].startswith("PC") and not r[1].startswith("KILLED")]
    if bad:
        print("\n⛔ positive control %s was not KILLED (%s) — the runner is broken "
              "and every row above is meaningless" % (bad[0][0], bad[0][1]))
    sys.exit(1 if bad else 0)
