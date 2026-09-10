import subprocess, os
SRC=open('netaddr.zig').read()
CAP=['/home/zak/workspace/zig-libs/scripts/capped']
env=dict(os.environ); env['ZIGLIBS_MEM_MAX']='4G'
for name,old,new in [
 ("M44b max_ip_text_len 45 -> 39 (true max output)","pub const max_ip_text_len = 45;","pub const max_ip_text_len = 39;"),
 ("M44c max_ip_text_len 45 -> 38 (ONE BELOW true max)","pub const max_ip_text_len = 45;","pub const max_ip_text_len = 38;"),
 ("M44d max_ip_text_len 45 -> 30","pub const max_ip_text_len = 45;","pub const max_ip_text_len = 30;"),
 ("M46 formatIp: drop the v4-mapped mixed-notation branch",
  "            if (Ip.isV4Mapped(b))\n                return std.fmt.bufPrint(buf, \"::ffff:{d}.{d}.{d}.{d}\", .{ b[12], b[13], b[14], b[15] }) catch unreachable;\n",""),
]:
    if SRC.count(old)!=1:
        print("%-52s SKIP(%d)"%(name[:52],SRC.count(old)),flush=True); continue
    open('mut/m.zig','w').write(SRC.replace(old,new))
    p=subprocess.run(CAP+['zig','test','mut/m.zig'],capture_output=True,text=True,env=env,timeout=600)
    out=p.stdout+p.stderr
    green=(p.returncode==0 and 'tests passed' in out)
    d=''
    if not green:
        for l in out.splitlines():
            if 'panic' in l or 'FAIL' in l or 'expected' in l: d=l.strip()[:95]; break
    print("%-52s %-17s %s"%(name[:52],"GREEN(unnoticed)" if green else "RED",d),flush=True)
