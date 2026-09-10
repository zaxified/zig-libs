import subprocess, os, sys, shutil
SRC = open('netaddr.zig').read()
MUTS = [
 ("M01 parseIp6 :: group-count cap 7->8",
  "if (head.len + tail.len > 7) return null;", "if (head.len + tail.len > 8) return null;"),
 ("M02 parseIp6 zone rejection removed",
  "if (std.mem.indexOfScalar(u8, text, '%') != null) return null; // no zone", "// mutated: zone check removed"),
 ("M03 parseIp6 full-form len!=8 -> len>8",
  "if (all.len != 8) return null;", "if (all.len > 8) return null;"),
 ("M04 parseGroupList empty-token check removed",
  "        if (tok.len == 0) return null;\n", "        // mutated\n"),
 ("M05 parseGroupList hex group len cap 4->5",
  "if (tok.len > 4) return null;", "if (tok.len > 5) return null;"),
 ("M06 parseGroupList v4 tail need not be last",
  "if (!v4_tail or it.next() != null) return null; // must be last", "if (!v4_tail) return null; // mutated"),
 ("M07 parseGroupList v4-tail position cap 6->7",
  "if (gl.len > 6) return null;", "if (gl.len > 7) return null;"),
 ("M08 parseGroupList group overflow cap 8->9",
  "if (gl.len >= 8) return null;", "if (gl.len >= 9) return null;"),
 ("M09 parseIp4 leading-zero rejection removed",
  "if (part.len > 1 and part[0] == '0') return null; // no leading zeros", "// mutated: leading zeros allowed"),
 ("M10 parseIp4 octet text len cap 3->4",
  "if (part.len == 0 or part.len > 3) return null;", "if (part.len == 0 or part.len > 4) return null;"),
 ("M11 parseIp4 octet value cap 255->999",
  "if (v > 255) return null;", "if (v > 999) return null;"),
 ("M12 parseIp4 too-many-parts cap 4->5",
  "if (i >= 4) return null;", "if (i >= 5) return null;"),
 ("M13 parseIp4 exact-4-parts -> at-least-3",
  "return if (i == 4) out else null;", "return if (i >= 3) out else null;"),
 ("M14 parsePort text len cap 5->6",
  "if (text.len == 0 or text.len > 5) return null;", "if (text.len == 0 or text.len > 6) return null;"),
 ("M15 parsePort u16 range check removed",
  "return if (v <= std.math.maxInt(u16)) @intCast(v) else null;", "return @truncate(v);"),
 ("M16 parseHostPort second-colon rejection removed",
  "if (std.mem.indexOfScalarPos(u8, text, colon + 1, ':') != null) return null;", "// mutated"),
 ("M17 parseHostPort empty-host (colon==0) check removed",
  "    if (colon == 0) return null;\n", "    // mutated\n"),
 ("M18 parseHostPort empty bracketed host check removed",
  "        if (host.len == 0) return null;\n", "        // mutated\n"),
 ("M19 parsePrefix bits leading-zero rejection removed",
  "    if (bits_text.len > 1 and bits_text[0] == '0') return null;\n", "    // mutated\n"),
 ("M20 parsePrefix bits<=width check widened to <=255",
  "if (v > widthOf(addr)) return null;", "if (v > 255) return null;"),
 ("M21 formatIp: compress a single zero group too",
  "if (best_len < 2) best_len = 0; // never compress a single group", "// mutated: single-group compression allowed"),
 ("M22 Prefix.contains family check removed",
  "        if (std.meta.activeTag(p.addr) != std.meta.activeTag(ip)) return false;\n", "        // mutated\n"),
 ("M23 sortDestinations candidate bound removed",
  "if (dsts.len > max_sort_candidates) return error.TooManyCandidates;", "if (false) return error.TooManyCandidates;"),
 ("M24 sortDestinationsWithSources length check removed",
  "if (dsts.len != srcs.len) return error.MismatchedLengths;", "if (false) return error.MismatchedLengths;"),
 ("M25 appendRangePrefixes terminator >= -> >",
  "if (block_last >= to) return;", "if (block_last > to) return;"),
 ("M26 mergePrefixes adjacency merge removed",
  "(ranges[j].from <= to or ranges[j].from == to + 1)", "(ranges[j].from <= to)"),
 ("M27 summarize from>to check removed",
  "    if (from > to) return error.InvalidRange;\n", "    // mutated\n"),
 ("M28 netMask bits clamp removed",
  "    const b = @min(bits, width);\n    if (b == 0) return 0;", "    const b = bits;\n    if (b == 0) return 0;"),
 ("M29 isPrivate 172.16/12 upper bound 31->32",
  "(q[0] == 172 and q[1] >= 16 and q[1] <= 31)", "(q[0] == 172 and q[1] >= 16 and q[1] <= 32)"),
 ("M30 commonPrefixLen v6 cap 64bits -> 128bits",
  "        .v6 => 8, // first 64 bits only", "        .v6 => 16, // mutated"),
 ("M31 Ip.eql v4/v6 cross-family -> compare as16",
  "                .v6 => false,\n            },\n            .v6 => |ba| switch (b) {\n                .v4 => false,",
  "                .v6 => std.mem.eql(u8, &a.as16(), &b.as16()),\n            },\n            .v6 => |ba| switch (b) {\n                .v4 => std.mem.eql(u8, &a.as16(), &b.as16()),"),
 ("M32 isV4Mapped drops the 0xffff marker check",
  "return std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;",
  "return std.mem.allEqual(u8, b[0..10], 0);"),
 ("M33 firstHost/lastHost reserve bound 30->29",
  "        const reserve = p.addr == .v4 and b <= 30;\n        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) net + 1 else net);",
  "        const reserve = p.addr == .v4 and b <= 29;\n        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) net + 1 else net);"),
 ("M34 overlaps uses longer prefix instead of shorter",
  "const m = netMask(w, @min(@min(p.bits, w), @min(other.bits, w)));",
  "const m = netMask(w, @max(@min(p.bits, w), @min(other.bits, w)));"),
 ("M35 containsPrefix bits comparison dropped",
  "        if (@min(other.bits, w) < @min(p.bits, w)) return false;\n", "        // mutated\n"),
 ("M36 hostMask clamp removed",
  "    const host = width - @min(bits, width);\n", "    const host = if (bits > width) 0 else width - bits;\n"),
 ("M37 AddrIterator: drop the exhaustion latch",
  "        if (it.cur == it.last) it.done = true else it.cur += 1;",
  "        it.cur +%= 1;"),
 ("M38 formatIp leftmost-tie -> rightmost-tie",
  "                    if (run_len > best_len) {", "                    if (run_len >= best_len) {"),
]
results=[]
for name, old, new in MUTS:
    if old not in SRC:
        results.append((name,"NOT-FOUND","pattern missing")); continue
    if SRC.count(old) != 1:
        results.append((name,"AMBIGUOUS","%d occurrences"%SRC.count(old))); continue
    open('mut/m.zig','w').write(SRC.replace(old,new))
    p=subprocess.run(['timeout','300','zig','test','mut/m.zig'],capture_output=True,text=True)
    out=(p.stdout+p.stderr)
    if 'error:' in out and 'tests passed' not in out and p.returncode!=0 and 'FAIL' not in out:
        status='COMPILE-ERR'
    elif p.returncode==0 and 'tests passed' in out:
        status='GREEN (suite did NOT notice)'
    else:
        status='RED'
    # which tests failed
    fails=[l for l in out.splitlines() if 'FAIL' in l or 'expected' in l.lower()][:2]
    results.append((name,status,fails[0][:110] if fails else ''))
    print("%-58s %s  %s" % (name, status, results[-1][2]), flush=True)
print()
print("GREEN (unnoticed) mutants:")
for n,s,d in results:
    if s.startswith('GREEN'): print("  ",n)
