#!/usr/bin/env python3
"""Two-gate mutation runner for `rawsock` (A1/rawsock.md F12).

Ported from the audit's own `A1/repro/rawsock/mut/mutate.py` (2026-09-05) per
CONVENTIONS.md #9: an instrument that checks ONE module belongs in that
module's own `tools/` directory (it needs a foreign toolchain -- Python --
not just `zig test`), never in the audit tree, or it rots silently and the
next audit rebuilds it from scratch. Mutation table, classification logic
and lane setup are UNCHANGED from the audit's version; only path defaults
were adjusted now that the script lives inside the checkout it targets
instead of beside it.

One mutation per directory, each with its OWN --cache-dir: a shared cache
has handed a stale binary to a runner before, and every mutant then
"passed". Each mutation is checked to have (a) actually changed the source
and (b) actually compiled -- the needle for a compile failure is
`\\.zig:\\d+:\\d+: error:`, because a bare `error:` is also how Zig
introduces a FAILED TEST.

TWO LANES, because `rawsock` is an instrument whose socket tests skip
themselves:

  host    plain `zig test` -- no CAP_NET_RAW, so the two socket tests
          SkipZigTest. This is what `zig build test-rawsock` does on any
          developer machine and in any CI container without the capability.
  netns   the same binary under `unshare -rn`, where root holds CAP_NET_RAW,
          so all 18 tests actually run.

  m0 is a NO-OP control that MUST survive (it catches a runner that reports
     every build as broken).
  m1 is a POSITIVE control that MUST die (it catches a runner that reports
     every build as green).

A mutation that turns a PASS into a SKIP is reported as SURVIVED-SKIP: the
gate stayed green while the thing under test stopped being tested.

⛔ This script runs raw `zig test` directly (twice per mutation, once under
`unshare -rn`) with its own per-mutation `--cache-dir` -- it is deliberately
OUTSIDE `scripts/modtest`'s single-cache, capped-resource envelope, the same
way `scripts/ctgrind.sh` and the interop `tools/` scripts in this repo are.
Do not fold it into `modtest`; do not run it from an agent session bound to
modtest-only gates. It is meant for a human, or an agent slot explicitly
cleared to run full/foreign-toolchain gates, at the campaign's own pace.

usage: [ROOT=<zig-libs checkout>] ./mutate.py [Debug|ReleaseSafe|ReleaseFast] [name...]

`ROOT` defaults to this script's own checkout (three directories up from
`modules/rawsock/tools/`); override it to point at a different worktree.
"""
import os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("ROOT") or os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if not os.path.isdir(os.path.join(ROOT, "modules", "rawsock")):
    sys.exit(f"ROOT={ROOT!r} does not look like a zig-libs checkout (no modules/rawsock) -- set ROOT explicitly")
MODE = sys.argv[1] if len(sys.argv) > 1 else "Debug"
ONLY = set(sys.argv[2:])
# Mutation trees are big (a full zig cache each) and must be droppable, so
# they go under SCRATCH -- point it at the repo's .zig-cache, never /tmp
# (tmpfs -- see CONVENTIONS.md's "big scratch data" rule).
WORK = os.environ.get("SCRATCH", os.path.join(ROOT, ".zig-cache", "rawsock-mutate"))
os.environ["TMPDIR"] = os.path.join(WORK, "tmp")
os.makedirs(os.environ["TMPDIR"], exist_ok=True)

# (name, nth-occurrence, old, new) -- all in modules/rawsock/src/root.zig
M = [
 ("m0_noop", 0,
  "//! rawsock — Linux AF_PACKET raw-frame capture + inject.",
  "//! rawsock (no-op control) — Linux AF_PACKET raw-frame capture + inject."),
 ("m1_poscontrol", 0,
  ".ethertype = std.mem.readInt(u16, frame[12..14], .big),",
  ".ethertype = std.mem.readInt(u16, frame[10..12], .big),"),

 # --- pure decoders -------------------------------------------------------
 ("m2_ethhdr_len_gone", 0, "if (frame.len < eth_hdr_len) return null;", ""),
 ("m3_ethhdr_len_weak", 0, "if (frame.len < eth_hdr_len) return null;", "if (frame.len < 1) return null;"),
 ("m4_ethhdr_srcdst_swap", 0,
  ".dst = frame[0..6].*,\n            .src = frame[6..12].*,",
  ".dst = frame[6..12].*,\n            .src = frame[0..6].*,"),
 ("m5_arp_len_gone", 0, "if (frame.len < request_len) return null;", ""),
 ("m6_arp_len_weak", 0, "if (frame.len < request_len) return null;", "if (frame.len < 22) return null;"),
 ("m7_arp_ethertype_gone", 0,
  "if (std.mem.readInt(u16, frame[12..14], .big) != eth_p.arp) return null;", ""),
 ("m8_arp_ethertype_hibyte", 0,
  "if (std.mem.readInt(u16, frame[12..14], .big) != eth_p.arp) return null;",
  "if ((std.mem.readInt(u16, frame[12..14], .big) >> 8) != (eth_p.arp >> 8)) return null;"),
 ("m9_arp_oper_gone", 0,
  "if (std.mem.readInt(u16, frame[20..22], .big) != 0x0002) return null; // not a reply", ""),
 ("m10_arp_oper_1bit", 0,
  "if (std.mem.readInt(u16, frame[20..22], .big) != 0x0002) return null; // not a reply",
  "if ((std.mem.readInt(u16, frame[20..22], .big) & 1) != 0) return null; // not a reply"),
 ("m11_arp_buildreq_target", 0,
  "@memcpy(f[38..42], &target_ip); // target IP",
  "_ = target_ip;\n        @memcpy(f[38..42], &src_ip); // target IP"),

 # --- hwaddr text ---------------------------------------------------------
 ("m12_hwaddr_len_weak", 0,
  "if (text.len != hwaddr_text_len) return null;",
  "if (text.len < hwaddr_text_len) return null;"),
 ("m13_hwaddr_sep_gone", 0, "if (sep != ':' and sep != '-') return null;", ""),
 ("m14_hwaddr_innersep_gone", 0, "if (i > 0 and text[off - 1] != sep) return null;", ""),

 # --- sockaddr_ll decode --------------------------------------------------
 ("m15_linkaddr_clamp_gone", 0,
  "const n = @min(@as(usize, sll.halen), hwaddr_len);",
  "const n = @as(usize, sll.halen);"),
 ("m16_linkaddr_endian_gone", 0,
  ".protocol = std.mem.bigToNative(u16, sll.protocol),",
  ".protocol = sll.protocol,"),

 # --- classic BPF ---------------------------------------------------------
 ("m17_filter_offset14", 0,
  "bpf.stmt(bpf.ld | bpf.h | bpf.abs, 12), // A = ethertype halfword at offset 12",
  "bpf.stmt(bpf.ld | bpf.h | bpf.abs, 14), // A = ethertype halfword at offset 12"),
 ("m18_filter_snaplen14", 0,
  "bpf.stmt(bpf.ret | bpf.k, 0x40000), // accept up to 256 KiB",
  "bpf.stmt(bpf.ret | bpf.k, 14), // accept up to 256 KiB"),
 ("m19_filter_jt_jf_swap", 0,
  "bpf.jump(bpf.jmp | bpf.jeq | bpf.k, ethertype, 0, 1), // if A == type: accept else drop",
  "bpf.jump(bpf.jmp | bpf.jeq | bpf.k, ethertype, 1, 0), // if A == type: accept else drop"),
 ("m20_setfilter_bounds_gone", 0,
  "if (prog.len == 0 or prog.len > std.math.maxInt(u16)) return error.InvalidFilter;", ""),

 # --- interface helpers ---------------------------------------------------
 ("m21_ifaceidx_namelen_gone", 0,
  "if (name.len == 0 or name.len > 15) return error.NoSuchInterface;", ""),
 ("m22_ifacename_nul_gone", 0,
  "const end = std.mem.indexOfScalar(u8, out, 0) orelse out.len;",
  "const end = out.len;"),
 ("m23_hwaddr_offset", 0, "@memcpy(&mac, req.un[2..8]);", "@memcpy(&mac, req.un[4..10]);"),
 ("m24_sockaddrin_offset", 0, "return req.un[4..8].*;", "return req.un[2..6].*;"),

 # --- socket path ---------------------------------------------------------
 # m25 updated 2026-09-11 (F12 port): the audit's original one-line pattern
 # (`if (opts.recv_timeout_ms != 0) setRcvTimeout(fd, opts.recv_timeout_ms);`,
 # a bare call with no error check) no longer exists -- `setRcvTimeout` was
 # made fallible and wired to `error.TimeoutFailed` since the audit (F13 in
 # A1/rawsock.md was exactly this: "the setsockopt's own `_ =` swallowed a
 # failure"). Same intent, current shape: delete the whole guarded call.
 ("m25_rcvtimeout_noop", 0,
  "        if (opts.recv_timeout_ms != 0) {\n            setRcvTimeout(fd, opts.recv_timeout_ms) catch return error.TimeoutFailed;\n        }\n",
  ""),
 ("m26_bind_gone", 0,
  "const idx = ifaceIndexOn(fd, name) catch return error.NoSuchInterface;\n            try bindPacket(fd, idx, ethertype);",
  "const idx = ifaceIndexOn(fd, name) catch return error.NoSuchInterface;\n            _ = idx;"),
 ("m27_bind_proto_zero", 0,
  "fn bindPacket(fd: i32, ifindex: i32, ethertype: u16) OpenError!void {\n    var sll = linux.sockaddr.ll{\n        .protocol = std.mem.nativeToBig(u16, ethertype),",
  "fn bindPacket(fd: i32, ifindex: i32, ethertype: u16) OpenError!void {\n    var sll = linux.sockaddr.ll{\n        .protocol = if (true) 0 else std.mem.nativeToBig(u16, ethertype),"),
 # m28 updated 2026-09-11 (F12 port): the receive-count variable was renamed
 # `n` -> `copied` since the audit; same truncation intent.
 ("m28_recv_trunc14", 0, ".bytes = buf[0..copied],", ".bytes = buf[0..@min(copied, 14)],"),
 ("m29_recv_ifindex_zero", 0, ".ifindex = la.ifindex,", ".ifindex = 0,"),
 ("m30_send_halen_zero", 0, ".halen = hwaddr_len,", ".halen = 0,"),
 ("m31_send_proto_native", 1,
  ".protocol = std.mem.nativeToBig(u16, ethertype),", ".protocol = ethertype,"),
 ("m32_promisc_type_zero", 0, ".type = PACKET_MR_PROMISC,", ".type = 0,"),
 ("m33_promisc_never_drop", 0,
  "const opt: u32 = if (on) linux.PACKET.ADD_MEMBERSHIP else linux.PACKET.DROP_MEMBERSHIP;",
  "const opt: u32 = if (on or true) linux.PACKET.ADD_MEMBERSHIP else linux.PACKET.DROP_MEMBERSHIP;"),
 # m34 updated 2026-09-11 (F12 port): the audit's original multi-line anchor
 # (PERM/ACCES switch through the start of the recv_timeout_ms guard) is no
 # longer contiguous -- an `opts.filter`/`opts.recv_buf_bytes` block (F4 in
 # A1/rawsock.md: filter attached FIRST, before bind/SO_RCVBUF/SO_RCVTIMEO)
 # now sits between `errdefer` and the timeout guard. Narrowed to the single
 # line that actually carries this mutation's intent (AccessDenied collapsed
 # into SocketFailed) -- same effect, robust to unrelated code shifting
 # nearby again.
 ("m34_open_accessdenied_gone", 0,
  "            .PERM, .ACCES => return error.AccessDenied,",
  "            .PERM, .ACCES => return error.SocketFailed,"),
 ("m35_openinject_bind_gone", 0,
  "        errdefer _ = linux.close(fd);\n        try bindPacket(fd, ifindex, 0);\n        return .{ .fd = fd };",
  "        errdefer _ = linux.close(fd);\n        _ = ifindex;\n        return .{ .fd = fd };"),
]

BUILD_ERR = re.compile(r"\.zig:\d+:\d+: error:")
ALLPASS = re.compile(r"All (\d+) tests passed\.")
MIXED = re.compile(r"(\d+) passed; (\d+) skipped; (\d+) failed\.")


def run(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1200, cwd=cwd)


def classify(out, rc, baseline):
    """-> (verdict, detail)"""
    if BUILD_ERR.search(out):
        m = BUILD_ERR.search(out)
        return "NOBUILD", (m.group(0) + " " + out[m.end():m.end() + 60].split("\n")[0]).strip()
    m = ALLPASS.search(out)
    if m and rc == 0:
        got = (int(m.group(1)), 0)
    else:
        m2 = MIXED.search(out)
        if m2:
            got = (int(m2.group(1)), int(m2.group(2)))
            if int(m2.group(3)) != 0:
                return "KILLED", f"{m2.group(1)} passed; {m2.group(2)} skipped; {m2.group(3)} failed"
        elif rc != 0:
            tail = [l for l in out.splitlines() if "panic" in l or "FAIL" in l or "error" in l]
            return "KILLED", (tail[0][:70] if tail else out.splitlines()[-1][:70] if out.splitlines() else "rc!=0")
        else:
            return "SURVIVED?", "no recognisable summary"
    if rc != 0:
        return "KILLED", f"rc={rc} {got[0]} passed"
    if got[1] > baseline[1]:
        return "SURVIVED-SKIP", f"{got[0]} pass, {got[1]} skip (baseline {baseline[0]}/{baseline[1]})"
    return "SURVIVED", f"{got[0]} pass, {got[1]} skip"


def gate(src_root, cache, netns):
    cmd = ["zig", "test", "-O" + MODE, "--dep", "netaddr",
           "-Mroot=" + src_root,
           "-Mnetaddr=" + os.path.join(ROOT, "modules", "netaddr", "src", "root.zig"),
           "--cache-dir", cache]
    if netns:
        cmd = ["unshare", "-rn", "env", "TMPDIR=" + os.environ["TMPDIR"]] + cmd
    r = run(cmd)
    return r.stdout + r.stderr, r.returncode


BASE = {"host": (16, 2), "netns": (18, 0)}

print(f"{'MUTATION':<30} {'HOST LANE':<16} {'NETNS LANE':<16} DETAIL   [mode={MODE}]")
tally = {}
for name, nth, old, new in M:
    if ONLY and name not in ONLY:
        continue
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    shutil.copytree(os.path.join(ROOT, "modules", "rawsock"), os.path.join(d, "rawsock"))
    p = os.path.join(d, "rawsock", "src", "root.zig")
    s = open(p).read()
    pos = -1
    for _ in range(nth + 1):
        pos = s.find(old, pos + 1)
        if pos < 0:
            break
    if pos < 0:
        print(f"{name:<30} {'SKIP':<16} {'':<16} pattern not found", flush=True)
        continue
    s2 = s[:pos] + new + s[pos + len(old):]
    if s2 == s:
        print(f"{name:<30} {'SKIP':<16} {'':<16} diff empty", flush=True)
        continue
    open(p, "w").write(s2)

    host_out, host_rc = gate(p, os.path.join(d, "zc"), netns=False)
    open(os.path.join(d, "out-host.txt"), "w").write(host_out)
    hv, hd = classify(host_out, host_rc, BASE["host"])

    if hv == "NOBUILD":
        nv, nd = "NOBUILD", ""
    else:
        ns_out, ns_rc = gate(p, os.path.join(d, "zc"), netns=True)
        open(os.path.join(d, "out-netns.txt"), "w").write(ns_out)
        nv, nd = classify(ns_out, ns_rc, BASE["netns"])

    key = f"{hv}/{nv}"
    tally[key] = tally.get(key, 0) + 1
    print(f"{name:<30} {hv:<16} {nv:<16} {nd or hd}", flush=True)

print("\ntally (host/netns):")
for k, v in sorted(tally.items()):
    print(f"  {k:<34} {v}")
