#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a message with N fields, to find where comptime work stops scaling.

WHY THIS EXISTS. This module builds its codec at comptime from `pb_fields`, so
the cost of a message is paid by the COMPILER, not at run time — and that cost is
invisible to every test, which uses small messages. A consumer with a generated
schema of several hundred fields is the first one to find the ceiling, and what
they hit is `error: evaluation exceeded N backwards branches`, which reads like
their mistake rather than ours. This produces the input that locates the ceiling.

WHAT IT NEEDS. Python; then a `zig` to compile what it wrote.

    python3 mkn.py 256            # writes probe_n.zig with 256 fields
    python3 mkn.py 512 100000     # ... and raise the branch quota

WHAT IT PRODUCES. `probe_n.zig` in the current directory: a message of N int32
fields, decoded once in `main`. Compile it and see whether the compiler accepts
it and how long it takes; the quota argument is what a consumer would have to
add, and is the number worth documenting for them.
"""
import sys

if len(sys.argv) < 2:
    print("usage: mkn.py <field-count> [eval-branch-quota]", file=sys.stderr)
    sys.exit(2)

n = int(sys.argv[1])
quota = int(sys.argv[2]) if len(sys.argv) > 2 else 0

s = ['const std = @import("std");\nconst pb = @import("protobuf");\nconst Field = pb.Field;\n']
s.append("pub const M = struct {\n")
for i in range(n):
    s.append("    f%d: i32 = 0,\n" % i)
s.append("    pub const pb_fields = .{\n")
for i in range(n):
    s.append("        .f%d = Field{ .number = %d, .kind = .int32 },\n" % (i, i + 1))
s.append("    };\n};\n")
s.append("pub fn main() !void {\n")
if quota:
    s.append("    @setEvalBranchQuota(%d);\n" % quota)
s.append("    const gpa = std.heap.smp_allocator;\n    var d = try pb.decode(M, gpa, &.{}, .{});\n    d.deinit();\n    if (d.value.f0 == 12345) return error.No;\n}\n")
open("probe_n.zig", "w").write("".join(s))
print(f"wrote probe_n.zig: {n} fields" + (f", quota {quota}" if quota else ""))
