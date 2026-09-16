#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation probe for `whois`: weaken or delete one guard at a time and see
whether the suite notices.

  RED    = at least one test failed  -> the guard is pinned by the suite
  GREEN  = the suite still passes    -> the guard is NOT pinned (a finding)
  NOLAND = the textual mutation did not apply -> reported as a failure, never
           silently as GREEN. A runner that fails open prints GREEN for a
           mutation that never happened, which reads as "the suite has a hole"
           when the truth is "nothing was tested".

WHY THIS EXISTS, and why it is mostly about one thing. Over half the mutations
below disarm an SSRF defence: `isSpecialUseHost`, the loopback / private /
link-local / unique-local / multicast / documentation checks, the referral depth
cap, the cycle guard. A whois client follows referrals to hosts the *response*
names, so every one of those is the only thing between a caller and a request
aimed at 127.0.0.1 or at cloud metadata at 169.254.169.254. None of them is
visible in a functional test that looks up a real domain and gets the right
answer back.

⚠ AN ANCHOR THAT MATCHES MORE THAN ONCE IS REFUSED, not applied to the first
hit. `str.replace(old, new, 1)` on a pattern with two sites mutates one of them
and leaves the other intact — a half-applied mutation whose verdict describes
neither the original code nor the mutant.

⚠ SEVEN ANCHORS ARE STALE against the current sources and report NOLAND:
M2, M3, M4 and M11 no longer occur at all; M9, M22 and M23 now occur TWICE.
Re-deriving them means re-reading those functions, not loosening the match.

WHAT IT NEEDS. A `zig` on PATH. The `netaddr` dependency is taken from this
repository (`modules/netaddr/src/root.zig`) -- the audit kept its own copy, which
by 2026-09-16 was 128 lines out of date.

    python3 mutate.py            # all 33
    python3 mutate.py M7 M13     # only these

WHAT IT PRODUCES. A verdict line per mutation, a tally, the list of guards the
suite does not pin, and the list that failed to apply. Exit 1 if a positive
control misbehaved -- `PC-ok` must stay GREEN and `PC-bad` must go RED, and if
either is wrong the runner is broken and no other row means anything.
"""
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
SRC = HERE.parent / "src"
NET = REPO / "modules" / "netaddr" / "src" / "root.zig"
WORK = REPO / ".zig-cache" / "whois-mutate"
MOD = WORK / "modsrc"


def restore():
    if MOD.exists():
        for f in MOD.iterdir():
            f.unlink()
        MOD.rmdir()
    MOD.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SRC, MOD)


def run_suite():
    r = subprocess.run(
        ["zig", "test", "--dep", "netaddr",
         "-Mroot=" + str(MOD / "root.zig"),
         "-Mnetaddr=" + str(NET),
         "--cache-dir", str(WORK / "zc")],
        capture_output=True, text=True, timeout=600,
    )
    return r.returncode, (r.stdout + r.stderr)


# (id, file, old, new, what)
M = [
    ("M1",  "root.zig", "        if (isSpecialUseHost(ref.host)) // SSRF guard: never chase into special-use space\n            return .{ .response = response, .chain = chain, .truncated = false };\n", "", "lookup: delete the SSRF guard entirely"),
    ("M2",  "root.zig", 'pub fn isSpecialUseHost(host: []const u8) bool {\n    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;', 'pub fn isSpecialUseHost(host: []const u8) bool {\n    if (true) return false;\n    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;', "isSpecialUseHost always false"),
    ("M3",  "root.zig", '    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;\n', "", "drop the `localhost` name check"),
    ("M4",  "root.zig", '    if (std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;\n', "", "drop the `.localhost` suffix check"),
    ("M5",  "root.zig", "        if (chain.count >= max_servers or !chain.append(ref.host))", "        if (false or !chain.append(ref.host))", "delete the referral DEPTH cap"),
    ("M6",  "root.zig", "        if (chain.contains(ref.host)) // self-referral / cycle: this is terminal", "        if (false) // self-referral / cycle: this is terminal", "delete the CYCLE guard"),
    ("M7",  "root.zig", "    for (query) |c| if (c == '\\r' or c == '\\n') return error.InvalidQuery;\n", "", "formatQuery: accept CR/LF (command injection)"),
    ("M8",  "root.zig", "    if (query.len > max_query_len or query.len + 2 > buf.len) return error.QueryTooLong;", "    if (query.len + 2 > buf.len) return error.QueryTooLong;", "formatQuery: drop max_query_len"),
    ("M9",  "root.zig", "        if (port == 0) return null;\n", "", "parseServerRef: accept port 0"),
    ("M10", "root.zig", '    } else if (std.mem.indexOf(u8, s, "://") != null) {\n        return null; // rwhois://, http://, … — not RFC 3912\n    }', "    }", "parseServerRef: accept any scheme"),
    ("M11", "root.zig", "    for (host) |c| {\n        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_')) return null;\n    }\n", "", "parseServerRef: drop the host charset check"),
    ("M12", "root.zig", "    if (host.len == 0 or host.len > max_host_len) return null;", "    if (host.len == 0) return null;", "parseServerRef: drop the host length cap"),
    ("M13", "root.zig", "        if (m != 0) return error.ResponseTooLarge;", "        if (false) return error.ResponseTooLarge;", "TcpTransport: drop the over-read probe (silent truncation)"),
    ("M14", "root.zig", "        if (n > response_buf.len) return error.TransportFailed;", "", "Transport.exchange: drop the length re-check"),
    ("M15", "root.zig", "        isDocumentationIp(ip);", "        false;", "isSpecialUseIp: drop RFC5737/3849 documentation space"),
    ("M16", "root.zig", "ip.isUniqueLocal() or ip.isPrivate() or", "ip.isUniqueLocal() or", "isSpecialUseIp: drop RFC1918 private"),
    ("M17", "root.zig", "    return ip.isUnspecified() or ip.isLoopback() or", "    return ip.isUnspecified() or", "isSpecialUseIp: drop loopback"),
    ("M18", "root.zig", "        ip.isMulticast() or ip.isUniqueLocal()", "        ip.isUniqueLocal()", "isSpecialUseIp: drop multicast"),
    ("M19", "root.zig", "ip.isLoopback() or ip.isLinkLocalUnicast() or\n", "ip.isLoopback() or\n", "isSpecialUseIp: drop link-local (cloud metadata)"),
    ("M20", "root.zig", "ip.isMulticast() or ip.isUniqueLocal() or", "ip.isMulticast() or", "isSpecialUseIp: drop unique-local fc00::/7"),
    ("M21", "root.zig", "    return ip.isUnspecified() or ip.isLoopback()", "    return ip.isLoopback()", "isSpecialUseIp: drop unspecified 0.0.0.0"),
    ("M22", "root.zig", "        if (line[key.len] != ':') continue;\n", "", "fieldValue: drop the colon-adjacency rule"),
    ("M23", "root.zig", "        if (value.len == 0) continue;\n", "", "fieldValue: return empty values as present"),
    ("M24", "root.zig", "        if (c.count >= capacity or host.len > max_host_len) return false;", "        if (host.len > max_host_len) return false;", "Chain.append: drop the capacity check"),
    ("M25", "root.zig", "    if (opts.root.len == 0 or !chain.append(opts.root)) return error.InvalidRoot;", "    if (!chain.append(opts.root)) return error.InvalidRoot;", "lookup: accept an empty root"),
    ("M26", "root.zig", "or query.len + 2 > buf.len) return error.QueryTooLong;", "or false) return error.QueryTooLong;", "formatQuery: drop the destination-buffer bound"),
    ("M27", "root.zig", '    if (std.mem.indexOfScalar(u8, s, \'/\')) |i| s = s[0..i]; // trailing "/" or path\n', "", "parseServerRef: stop stripping the path"),
    ("M28", "root.zig", '    "refer",\n    "ReferralServer",', '    "ReferralServer",\n    "refer",', "referral_keys: swap the top two priorities"),
    ("M29", "root.zig", "            if (std.ascii.eqlIgnoreCase(c.get(i), host)) return true;", "            if (std.mem.eql(u8, c.get(i), host)) return true;", "Chain.contains: case-SENSITIVE cycle guard"),
    ("M30", "root.zig", "        if (sr.err) |e| if (e == error.Canceled) return error.Canceled;", "", "TcpTransport: fold Canceled back into TransportFailed"),
    ("M31", "root.zig", "    const max_servers: usize = @min(@as(usize, opts.max_referrals) + 1, Chain.capacity);", "    const max_servers: usize = @as(usize, opts.max_referrals) + 1;", "lookup: drop the clamp of max_referrals to Chain.capacity"),
    # positive controls
    ("PC-ok",  "root.zig", "// ── constants ─", "// mutation-runner no-op marker\n// ── constants ─", "POSITIVE CONTROL: no-op edit, must stay GREEN"),
    ("PC-bad", "root.zig", "    buf[query.len] = '\\r';\n    buf[query.len + 1] = '\\n';", "    buf[query.len] = '\\n';\n    buf[query.len + 1] = '\\r';", "POSITIVE CONTROL: break the wire framing, must go RED"),
]


def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    print(f"{'ID':<8} {'VERDICT':<8} {'landed':<7} what")
    tally = {"RED": 0, "GREEN": 0, "NOLAND": 0}
    greens, nolands = [], []
    controls = {}
    for mid, fname, old, new, what in M:
        if only and mid not in only:
            continue
        restore()
        p = MOD / fname
        s = p.read_text()
        hits = s.count(old)
        if hits != 1:
            why = "absent" if hits == 0 else f"{hits} sites"
            print(f"{mid:<8} {'NOLAND':<8} {'no':<7} {what}   [{why}]")
            tally["NOLAND"] += 1
            nolands.append((mid, what, why))
            if mid.startswith("PC"):
                controls[mid] = "NOLAND"
            continue
        p.write_text(s.replace(old, new, 1))
        # diff-verify the mutation is on disk
        landed = subprocess.run(["diff", "-q", str(SRC / fname), str(p)],
                                capture_output=True).returncode != 0
        rc, out = run_suite()
        verdict = "RED" if rc != 0 else "GREEN"
        tally[verdict] += 1
        if mid.startswith("PC"):
            controls[mid] = verdict
        elif verdict == "GREEN":
            greens.append((mid, what))
        note = ""
        if mid == "PC-ok":
            note = "  (expect GREEN)"
        if mid == "PC-bad":
            note = "  (expect RED)"
        print(f"{mid:<8} {verdict:<8} {'yes' if landed else 'NO':<7} {what}{note}")
        sys.stdout.flush()
    restore()
    print()
    print(f"RED {tally['RED']}   GREEN {tally['GREEN']}   NOLAND {tally['NOLAND']}")
    if greens:
        print("\nSURVIVED (guard not pinned by the suite):")
        for mid, what in greens:
            print(f"  {mid}: {what}")
    if nolands:
        print("\nFAILED TO APPLY (reported as failures, not as GREEN):")
        for mid, what, why in nolands:
            print(f"  {mid}: {what}   [{why}]")

    # The controls decide whether anything above is evidence.
    bad = []
    if controls.get("PC-ok") not in (None, "GREEN"):
        bad.append(f"PC-ok is {controls['PC-ok']}, expected GREEN")
    if controls.get("PC-bad") not in (None, "RED"):
        bad.append(f"PC-bad is {controls['PC-bad']}, expected RED")
    if bad:
        print("\n⛔ " + "; ".join(bad) + " — the runner is broken and every row "
              "above is meaningless")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
