import subprocess, os, sys
SRC=open('netaddr.zig').read()
CAP=['/home/zak/workspace/zig-libs/scripts/capped']
env=dict(os.environ); env['ZIGLIBS_MEM_MAX']='4G'
MUTS=[
 ("M10b parseIp4 octet-text cap 3->6 (u16 overflow reachable?)",
  "if (part.len == 0 or part.len > 3) return null;", "if (part.len == 0 or part.len > 6) return null;"),
 ("M14b parsePort text cap 5->12 (u32 overflow reachable?)",
  "if (text.len == 0 or text.len > 5) return null;", "if (text.len == 0 or text.len > 12) return null;"),
 ("M19b parsePrefix bits_text cap 3->6",
  "if (bits_text.len == 0 or bits_text.len > 3) return null;", "if (bits_text.len == 0 or bits_text.len > 6) return null;"),
 ("M33b lastHost reserve bound 30->29 (the /30 edge)",
  "        const reserve = p.addr == .v4 and b <= 30;\n        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) last - 1 else last);",
  "        const reserve = p.addr == .v4 and b <= 29;\n        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) last - 1 else last);"),
 ("M39 Prefix.eql ignores bits",
  "return a.bits == b.bits and a.addr.eql(b.addr);","return a.addr.eql(b.addr);"),
 ("M40 Ip.unmap made a no-op",
  "            .v6 => |b| if (isV4Mapped(b)) .{ .v4 = b[12..16].* } else ip,",
  "            .v6 => ip,"),
 ("M41 policy table: drop the ::ffff:/96 row",
  '    policyEntry("::ffff:0.0.0.0", 96, 35, 4),\n', ''),
 ("M42 scopeOf: loopback no longer link-local",
  "    if (ip.isLoopback() or ip.isLinkLocalUnicast()) return .link_local;",
  "    if (ip.isLinkLocalUnicast()) return .link_local;"),
 ("M43 selectSource family filter removed",
  "        if ((c.unmap() == .v4) != want_v4) continue;\n", ""),
 ("M44 max_ip_text_len 45 -> 40", "pub const max_ip_text_len = 45;", "pub const max_ip_text_len = 40;"),
 ("M45 summarize family-mismatch check removed  [EXPECT OOM-KILL]",
  "    if (fam != std.meta.activeTag(r.to)) return error.InvalidRange;\n", ""),
]
only=sys.argv[1:] if len(sys.argv)>1 else None
for name,old,new in MUTS:
    if only and not any(name.startswith(o) for o in only): continue
    if SRC.count(old)!=1:
        print("%-56s SKIP(%d occurrences)"%(name[:56],SRC.count(old)),flush=True); continue
    open('mut/m.zig','w').write(SRC.replace(old,new))
    p=subprocess.run(CAP+['zig','test','mut/m.zig'],capture_output=True,text=True,env=env,timeout=600)
    out=p.stdout+p.stderr
    green=(p.returncode==0 and 'tests passed' in out)
    detail=''
    if not green:
        if p.returncode==137 or 'Killed' in out: detail='KILLED BY CGROUP CAP (exit 137) — unbounded allocation'
        else:
            for l in out.splitlines():
                if 'panic' in l or 'FAIL' in l or 'expected' in l: detail=l.strip()[:105]; break
    print("%-56s %-18s %s"%(name[:56], "GREEN(unnoticed)" if green else "RED(rc=%d)"%p.returncode, detail),flush=True)
