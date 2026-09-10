#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Diff this repo's kernel-UAPI netlink constants against the installed
kernel headers. The STANDING version of campaign C-09 (wave-2 audit, K3 /
`ethtool` F2, `nl80211` F3, `conntrack` F3, `devlink` F1-half).

Why this exists: the wave-2 audit hand-diffed every constant in `conntrack`,
`devlink`, `ethtool` and `nl80211` against this host's `/usr/include/linux`
headers ONCE (327/327, 283/283, 111/111, 154/154, all matched) and proved with
a fault injection that nothing in the repo would have caught a wrong value —
a mutated constant (`CTA_COUNTERS.PACKETS32` 3 -> 9, or equivalent in the
other three modules) compiled and the whole `zig build test-<module>` suite
stayed GREEN, because the module's own goldens read the mutated symbol on
both the encode and the decode side (consistent-mutation blindness). A
one-time manual sweep does not stay true after the next edit; this script is
the thing that keeps checking.

What it does, per module:
  1. Walks the module's own `uapi.zig` (or, for `conntrack`, the constant
     block at the top of `wire.zig`) and structurally extracts every leaf
     integer constant inside a top-level `pub const X = struct { ... }`
     namespace or `pub const X = enum(T) { ... }` (implicit-increment aware).
     Only plain integer literals are collected -- an expression
     (`@intFromEnum(...)`, a bitwise-OR of two other constants, ...) is
     skipped rather than guessed at.
  2. Parses the module's registered kernel header(s): `#define NAME VALUE`
     and C `enum { ... }` blocks (implicit-increment aware, and tolerant of a
     `1 << n` / hex / decimal right-hand side).
  3. For each Zig constant, tries the module's registered kernel-name
     prefixes in order (e.g. ethtool constants are `ETHTOOL_A_<path>` for
     attributes but `ETHTOOL_<path>` for message types -- both are tried) and
     compares the VALUE against whichever prefixed name the kernel header
     actually defines.

Every constant lands in one of three buckets:
  MATCHED    the kernel header defines a same-named constant with the same
             value.
  MISMATCH   the kernel header defines a same-named constant with a
             DIFFERENT value -- this is the real finding: our source drifted
             from the kernel's OS ABI.
  unresolved (not printed by default) -- no candidate prefix produced a name
             the header defines. This is NOT a failure: it usually means the
             constant is not a simple `#define`/enum entry (an OUI-composed
             cipher suite, a positional-only ABI constant, ...) or this
             module's prefix table is incomplete. Silently ignoring what it
             cannot verify, rather than guessing, is what keeps a MISMATCH
             meaningful.

Exit code is 0 iff every module checked had zero MISMATCHes -- a module whose
kernel headers are not installed on this host is SKIPPED, not failed, so this
script stays runnable (and green) on a host without `linux-libc-dev`/kernel
headers; it simply verifies nothing on that host. It is deliberately NOT a
`zig build test` gate for the same reason -- a build that only passes with
specific host packages installed is not a build the repo can require
everywhere. Run it by hand, or wire it into whatever this host's CI is (see
`scripts/check-citations.py` for the same non-gated-build precedent).

Usage:
    scripts/check-uapi-consts.py                     # every registered module
    scripts/check-uapi-consts.py ethtool nl80211      # just these
    scripts/check-uapi-consts.py --verbose            # print every MATCHED too

Python 3 stdlib only -- no pip packages, no network.
"""
import argparse
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Per-module: which of the module's own source files carry the constants,
# which installed kernel headers to diff against, and which prefixes to try
# (in order) when turning a dotted Zig constant name into a candidate kernel
# macro/enum name. `conntrack`'s own namespace names (`CTA`, `IPS`, ...) are
# already the kernel's own prefix, hence the empty string.
MODULES = {
    "ethtool": {
        "zig_files": ["modules/ethtool/src/uapi.zig"],
        "headers": [
            "/usr/include/linux/ethtool_netlink_generated.h",
            "/usr/include/linux/ethtool_netlink.h",
            "/usr/include/linux/ethtool.h",
            "/usr/include/linux/if.h",
        ],
        # `""` matters: the bare `PORT_*`, `DUPLEX_*`, `XCVR_*`, `ETH_SS_*` and
        # `AUTONEG_*` families carry no `ETHTOOL` prefix at all.
        "prefixes": ["ETHTOOL_A_", "ETHTOOL_", ""],
        # Suffixes are scoped to a namespace on purpose. `ETHTOOL_MSG_X_GET`
        # and `ETHTOOL_MSG_X_GET_REPLY` are BOTH real constants one apart, so
        # an unscoped bare-name attempt resolves every reply id against the
        # request id and reports 50 MISMATCHes that are not there. `_NTF`
        # names carry their own suffix, hence the `""` fallback inside REPLY.
        "suffixes": {"REPLY": ["_REPLY", ""], "LINK_MODE": ["_BIT"]},
        # Where this repo's namespace is not the kernel's. `REPLY` -> `MSG`
        # covers the 50 reply/notification ids (`ETHTOOL_MSG_<X>_REPLY`, and
        # the `_NTF` names which already end in their own suffix).
        "namespace_aliases": {
            "REPLY": "MSG",
            "StringSetId": "ETH_SS",
            "StatsGroup": "STATS",
            "StatsSrc": "MAC_STATS_SRC",
            "Port": "PORT",
            "Duplex": "DUPLEX",
            "Transceiver": "XCVR",
            "MasterSlaveCfg": "MASTER_SLAVE_CFG",
            "MasterSlaveState": "MASTER_SLAVE_STATE",
            "family_version": "GENL_VERSION",
        },
        # The handful whose kernel name is not derivable by any rule.
        "member_aliases": {
            "StringSetId.self_test": "ETH_SS_TEST",
            "MdiX.mdi": "ETH_TP_MDI",
            "MdiX.mdi_x": "ETH_TP_MDI_X",
            "MdiX.auto": "ETH_TP_MDI_AUTO",
            "MdiX.invalid": "ETH_TP_MDI_INVALID",
            "ifnamesize": "IFNAMSIZ",
        },
        # `I2C_ADDRESS_LOW`/`_HIGH` are SFF-8472 addresses this repo names
        # itself; the kernel has no macro for them. If this number grows,
        # something stopped being checked.
        "unresolved_budget": 2,
    },
    "nl80211": {
        "zig_files": ["modules/nl80211/src/uapi.zig"],
        "headers": [
            "/usr/include/linux/nl80211.h",
            "/usr/include/linux/genetlink.h",
            "/usr/include/linux/if.h",
        ],
        # `""` reaches the `CTRL_ATTR_*`/`CTRL_ATTR_MCAST_GRP_*` families in
        # genetlink.h, which carry no `NL80211`/`GENL` prefix.
        "prefixes": ["NL80211_", "GENL_", ""],
        # Read out of `/usr/include/linux/nl80211.h`, not guessed: the
        # regulatory-rule attributes live in the kernel's flat `NL80211_ATTR_`
        # namespace, and the two regulatory enums have their own spellings.
        "namespace_aliases": {
            "REG_RULE_ATTR": "ATTR",
            "DfsRegion": "DFS",
            "RegType": "REGDOM_TYPE",
        },
        "member_aliases": {
            "ifnamsiz": "IFNAMSIZ",
        },
        # Repo-local constants with no kernel spelling on this host:
        # `family_version` (the genl family version this module speaks, not an
        # ABI macro), `pmk_len` and `max_ssid_len` (802.11 spec constants —
        # `IEEE80211_MAX_SSID_LEN` and `WLAN_PMK_LEN` live in the kernel tree's
        # `ieee80211.h`, which is not exported to `/usr/include/linux`).
        # If this number grows, something stopped being checked.
        "unresolved_budget": 3,
    },
    "devlink": {
        "zig_files": ["modules/devlink/src/uapi.zig"],
        "headers": ["/usr/include/linux/devlink.h"],
        "prefixes": ["DEVLINK_"],
        # Where the kernel's namespace is not this repo's namespace. Each one
        # was read out of `/usr/include/linux/devlink.h`, not guessed:
        # `InlineMode.none` is `DEVLINK_ESWITCH_INLINE_MODE_NONE`, and the
        # parameter types live under the kernel's newer `VAR_ATTR_TYPE`
        # spelling.
        "namespace_aliases": {
            "InlineMode": "ESWITCH_INLINE_MODE",
            "EncapMode": "ESWITCH_ENCAP_MODE",
            "HealthState": "HEALTH_REPORTER_STATE",
            "ParamType": "VAR_ATTR_TYPE",
        },
        # Repo-local sizing constants (`bus_name_max`, `ifnamesize`, …) that
        # have no kernel spelling. Every enum member resolves; if this number
        # grows, something stopped being checked.
        "unresolved_budget": 7,
    },
    "conntrack": {
        "zig_files": ["modules/conntrack/src/wire.zig"],
        "headers": [
            "/usr/include/linux/netfilter/nfnetlink_conntrack.h",
            "/usr/include/linux/netfilter/nf_conntrack_common.h",
            "/usr/include/linux/netfilter/nf_conntrack_tcp.h",
            "/usr/include/linux/netfilter/nfnetlink.h",
            "/usr/include/linux/in.h",
            "/usr/include/linux/in6.h",
            # glibc, not the kernel: `AF_*`/`PF_*` are not in `linux/socket.h`.
            # A host without this exact path loses two constants to the
            # unresolved bucket, which fails the budget — the right way round.
            "/usr/include/x86_64-linux-gnu/bits/socket.h",
        ],
        "prefixes": [""],
        # ⚠ The comment that used to sit here said these were "repo-local sizing
        # constants and a few names this host's headers do not carry". 22 of the
        # 23 had a kernel spelling all along — the third module in a row whose
        # unresolved bucket was written off rather than read (2026-09-02).
        "namespace_aliases": {
            "TcpState": "TCP_CONNTRACK",
            "IPPROTO": "IPPROTO",
            "Family": "PF",
        },
        "member_aliases": {
            # The kernel puts the width before the field, this repo after it.
            "CTA_COUNTERS.PACKETS32": "CTA_COUNTERS32_PACKETS",
            "CTA_COUNTERS.BYTES32": "CTA_COUNTERS32_BYTES",
            # The socket families are `PF_INET`/`PF_INET6`, not `PF_IPV4`.
            "Family.ipv4": "PF_INET",
            "Family.ipv6": "PF_INET6",
        },
        # `nfgenmsg_len` is a repo-local sizing constant, and
        # `TcpState.syn_sent2` is a `#define` whose right-hand side is another
        # identifier (`TCP_CONNTRACK_LISTEN`), which the header parser does not
        # chase. If this number grows, something stopped being checked.
        "unresolved_budget": 2,
    },
    "netlink": {
        # `bridge.zig`'s ~100 hand-transcribed AF_BRIDGE constants (audit
        # finding `netlink` F3) -- previously outside this gate entirely.
        # The module's own namespace names (`IFLA_BR`, `IFLA_BRPORT`,
        # `IFLA_BRIDGE`, `BRIDGE_FLAGS`, `BRIDGE_MODE`, `BR_STATE`) are
        # already the kernel's own prefix, same shape as `conntrack` below.
        #
        # `root.zig` added 2026-09-10 (audit finding A6): ~90 hand-transcribed
        # rtnetlink constants (`AF`, `IFF`, `RTA`, `NDA`, `NUD`, `RT_TABLE`,
        # `RT_SCOPE`, `RTN`, `RTPROT`, `IFA_F`, `NTF`, `IFLA_INFO`) were live
        # and completely outside this gate -- only `bridge.zig`'s ~100 were
        # checked. Every one of those namespaces is already the kernel's own
        # prefix too (`NUD.PERMANENT` -> `NUD_PERMANENT`), so no aliases were
        # needed, same as `bridge.zig`.
        "zig_files": ["modules/netlink/src/bridge.zig", "modules/netlink/src/root.zig"],
        "headers": [
            "/usr/include/linux/if_link.h",
            "/usr/include/linux/if_bridge.h",
            "/usr/include/linux/rtnetlink.h",
            "/usr/include/linux/neighbour.h",
            "/usr/include/linux/if.h",
            "/usr/include/linux/if_addr.h",
            "/usr/include/linux/netlink.h",
            # glibc, not the kernel: `AF_*` is not in `linux/socket.h` (see
            # `conntrack`'s own entry for the same caveat and the same path).
            "/usr/include/x86_64-linux-gnu/bits/socket.h",
        ],
        "prefixes": [""],
        # repo-local constants: bridge.zig's 3 (`bridge_vlan_info_len`,
        # `vlan_id_max`, `vlan_id_min`) plus root.zig's 4 sizing constants
        # with no kernel macro spelling (`ifinfomsg_len`, `ifaddrmsg_len`,
        # `rtmsg_len`, `ndmsg_len` -- `ifnamsiz` DOES resolve, against
        # `if.h`'s `IFNAMSIZ`). If this number grows, something stopped
        # being checked.
        "unresolved_budget": 7,
    },
    "genetlink": {
        # Audit finding F9: genetlink owns `GENL_ID_CTRL`, `CTRL_CMD_*` and
        # `CTRL_ATTR_*` for four consumers (`nl80211`, `ethtool`, `devlink`,
        # `wireguard`), but until now the only automatic check of those
        # numbers was `nl80211`'s own private copy in `uapi.zig` -- which
        # SPEC's backlog plans to delete once `nl80211`/`ethtool` adopt the
        # shared resolver, at which point genetlink's constants would have
        # had no UAPI check left anywhere. Unlike `ethtool`/`nl80211`/
        # `devlink`, genetlink has no separate `uapi.zig`: its constants live
        # alongside the resolver logic in `root.zig` itself.
        "zig_files": ["modules/genetlink/src/root.zig"],
        "headers": ["/usr/include/linux/genetlink.h"],
        "prefixes": [""],
        # `header_len` (this module's own sizing constant, not a kernel
        # macro name) and `GENL_ID_CTRL` (the kernel spells it
        # `NLMSG_MIN_TYPE` inside `linux/netlink.h`, a different header this
        # single-header entry does not cross-reference -- `header_constants`
        # evaluates each header with its own macro table, so a `#define`
        # whose value is another header's macro never resolves here). If
        # this number grows, something stopped being checked.
        "unresolved_budget": 2,
    },
}

# ── Zig side: structurally extract dotted-name -> int from a uapi.zig-shaped
#    file (a top-level namespace `struct`/`enum` block per const-table). ────

_STRUCT_OPEN = re.compile(r'^\s*pub const (\w+)\s*=\s*(?:packed\s+)?struct\s*\{\s*$')
_ENUM_OPEN = re.compile(r'^\s*pub const (\w+)\s*=\s*enum\([^)]*\)\s*\{\s*$')
_CLOSE = re.compile(r'^\s*\};?\s*$')
_LEAF = re.compile(r'^\s*pub const (\w+)\s*(?::\s*[\w\[\]\.\?]+\s*)?=\s*(.+?);\s*$')
_INT_LITERAL = re.compile(r'^(0[xX][0-9a-fA-F]+|\d+)$')


def _strip_line_comment(line):
    i = line.find("//")
    return line[:i] if i != -1 else line


def _parse_int_literal(tok):
    tok = tok.strip()
    m = _INT_LITERAL.match(tok)
    return int(tok, 0) if m else None


def zig_constants(path):
    """dotted-namespace -> int, for every plain-integer leaf inside a
    top-level `pub const X = struct {...}` / `enum(T) {...}` block. Anything
    not shaped like this repo's generated-looking const tables (a function, a
    non-literal expression, an enum entry split across lines) is skipped, not
    guessed at."""
    out = {}
    stack = []  # [{"name":.., "kind": "struct"|"enum", "next": int|None}]
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = _strip_line_comment(raw)
            if not line.strip():
                continue
            m = _STRUCT_OPEN.match(line)
            if m:
                stack.append({"name": m.group(1), "kind": "struct"})
                continue
            m = _ENUM_OPEN.match(line)
            if m:
                stack.append({"name": m.group(1), "kind": "enum", "next": 0})
                continue
            if _CLOSE.match(line):
                if stack:
                    stack.pop()
                continue
            prefix = ".".join(s["name"] for s in stack)
            if stack and stack[-1]["kind"] == "enum":
                for entry in line.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    em = re.match(r'^(\w+)\s*(=\s*(.+))?$', entry)
                    if not em:
                        continue
                    name = em.group(1)
                    if em.group(3):
                        v = _parse_int_literal(em.group(3))
                        stack[-1]["next"] = (v + 1) if v is not None else None
                    else:
                        v = stack[-1]["next"]
                        if v is None:
                            continue
                        stack[-1]["next"] = v + 1
                    if v is not None:
                        out[f"{prefix}.{name}" if prefix else name] = v
                continue
            m = _LEAF.match(line)
            if m:
                name, expr = m.group(1), m.group(2)
                v = _parse_int_literal(expr)
                if v is not None:
                    out[f"{prefix}.{name}" if prefix else name] = v
    return out


# ── C side: #define + enum from an installed kernel header. ────────────────

_SAFE_EXPR = re.compile(r'^[0-9A-Za-z_+\-<>()\s]+$')


def _strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _strip_preprocessor(text):
    """Drop every `#...` directive line (and its `\\`-continuations). Several
    of these headers embed a `#define` *inside* an `enum { ... }` block (e.g.
    `nfnetlink_conntrack.h`'s `#define CTA_NAT CTA_NAT_SRC` between two real
    entries, `devlink.h`'s multi-line `#define DEVLINK_CMD_ESWITCH_MODE_GET`).
    Left in, a directive line has no top-level comma, so splitting the enum
    body on `,` folds it into the following entry, which then fails the
    `NAME` / `NAME = VALUE` shape and gets silently dropped **without**
    advancing the implicit-increment counter — every entry after it is then
    off by however many directives preceded it. Comma-splitting must never
    see these lines."""
    out_lines = []
    continuing = False
    for line in text.split("\n"):
        if continuing:
            continuing = line.rstrip().endswith("\\")
            continue
        if re.match(r"^[ \t]*#", line):
            continuing = line.rstrip().endswith("\\")
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _eval_c_int(expr, symtab):
    expr = expr.strip().rstrip(",")
    # Drop a trailing integer-literal suffix (1U, 0x10UL, ...).
    expr = re.sub(r'\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b', r'\1', expr)
    if not expr or not _SAFE_EXPR.match(expr):
        return None

    def repl(m):
        name = m.group(0)
        return str(symtab[name]) if name in symtab else name

    substituted = re.sub(r"[A-Za-z_]\w*", repl, expr)
    if not _SAFE_EXPR.match(substituted):
        return None
    try:
        return eval(substituted, {"__builtins__": {}}, {})  # noqa: S307 -- whitelisted chars only
    except Exception:
        return None


def header_constants(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        text = _strip_c_comments(f.read())
    out = {}
    for m in re.finditer(r'^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(?!\()[ \t]+(.+)$', text, re.M):
        name, expr = m.group(1), m.group(2).strip()
        v = _eval_c_int(expr, out)
        if v is not None:
            out[name] = v
    enum_text = _strip_preprocessor(text)
    for em in re.finditer(r'\benum\b[^{};]*\{(.*?)\}', enum_text, re.S):
        next_val = 0
        for entry in em.group(1).split(","):
            entry = entry.strip()
            if not entry:
                continue
            nm = re.match(r'^([A-Za-z_]\w*)\s*(=\s*(.+))?$', entry, re.S)
            if not nm:
                continue
            name = nm.group(1)
            if nm.group(3):
                v = _eval_c_int(nm.group(3), out)
                next_val = (v + 1) if v is not None else None
            else:
                v = next_val
                if v is not None:
                    next_val += 1
            if v is not None and name not in out:
                out[name] = v
    return out


# ── driver ───────────────────────────────────────────────────────────────


def _camel_to_snake_upper(seg):
    """`PortType` -> `PORT_TYPE`, `Cmd` -> `CMD`, `ATTR` -> `ATTR`.

    The kernel snake_cases what this repo spells in CamelCase, and until
    2026-09-02 this function only produced the concatenated form -- so
    `PortType.eth` asked the header for `DEVLINK_PORTTYPE_ETH` while the
    kernel spells it `DEVLINK_PORT_TYPE_ETH`, and EVERY member of eight
    devlink enums (plus 87 in ethtool and 18 in nl80211) fell into the
    unresolved bucket that nothing printed and nothing failed. Twenty of
    devlink's could be given a wrong value with the whole suite green.
    """
    out = []
    for i, ch in enumerate(seg):
        if ch.isupper() and i > 0 and (seg[i - 1].islower() or seg[i - 1].isdigit()):
            out.append("_")
        out.append(ch)
    return "".join(out).upper()


def candidate_names(dotted, prefixes, aliases=None, suffixes=None, members=None):
    if members and dotted in members:
        return [members[dotted]]
    segs = dotted.split(".")
    sfxs = [""]
    if suffixes:
        sfxs = suffixes.get(segs[0], suffixes.get("*", [""]))
    if aliases and segs[0] in aliases:
        segs = [aliases[segs[0]]] + segs[1:]
    # `u8_`/`type_` are Zig keyword escapes; the kernel has no trailing '_'.
    tail_variants = {segs[-1], segs[-1].rstrip("_")}
    bases = set()
    for tail in tail_variants:
        head = segs[:-1]
        bases.add("_".join(head + [tail]).upper())
        bases.add("_".join([_camel_to_snake_upper(h) for h in head] + [tail.upper()]))
        # Case-PRESERVING variant: the kernel spells its link-mode bits
        # `ETHTOOL_LINK_MODE_10baseT_Half_BIT`, mixed case and all, so an
        # upper-cased candidate can never match one.
        bases.add("_".join(head + [tail]))
    return [
        p + b + sfx
        for p in prefixes
        for b in sorted(bases)
        for sfx in sfxs
    ]


def check_module(name, cfg, verbose):
    missing_headers = [h for h in cfg["headers"] if not os.path.isfile(h)]
    if len(missing_headers) == len(cfg["headers"]):
        print(f"{name}: SKIP (no kernel header found on this host: {cfg['headers']})")
        return "skip", 0, 0, 0

    kernel = {}
    for h in cfg["headers"]:
        if os.path.isfile(h):
            kernel.update(header_constants(h))

    zig = {}
    for zf in cfg["zig_files"]:
        zig.update(zig_constants(os.path.join(REPO_ROOT, zf)))

    matched = mismatched = unresolved = 0
    mismatches = []
    unresolved_names = []
    for dotted, ours in sorted(zig.items()):
        # `_` is Zig's non-exhaustive-enum marker, not a constant anybody could
        # look up. Counting it as "unresolved" put noise in the one number that
        # is supposed to mean "something here is unchecked".
        if dotted.endswith("._"):
            continue
        found = None
        for cand in candidate_names(
            dotted,
            cfg["prefixes"],
            cfg.get("namespace_aliases"),
            cfg.get("suffixes"),
            cfg.get("member_aliases"),
        ):
            if cand in kernel:
                found = (cand, kernel[cand])
                break
        if found is None:
            unresolved += 1
            unresolved_names.append(dotted)
            continue
        cand, theirs = found
        if theirs == ours:
            matched += 1
            if verbose:
                print(f"  MATCHED  {name}: {dotted} = {ours} == {cand}")
        else:
            mismatched += 1
            mismatches.append((dotted, ours, cand, theirs))

    print(
        f"{name}: {matched} matched, {mismatched} MISMATCH, "
        f"{unresolved} unresolved (no candidate kernel name found), "
        f"{len(zig)} constants scanned"
    )
    for dotted, ours, cand, theirs in mismatches:
        print(f"  MISMATCH {name}: {dotted} = {ours} in this repo, but kernel {cand} = {theirs}")

    # ⛔ UNRESOLVED IS NOT "FINE". A constant nothing could look up is a
    # constant nothing checked, and until 2026-09-02 the count was printed as a
    # bare number with the names hidden even under `--verbose` -- so devlink
    # read "154 matched, 0 MISMATCH" while eight of its enums, including the
    # ones that drive `setPortType`, `setParam` (device NVRAM) and
    # `setEswitch`, were not being checked at all. The names are printed now,
    # and a module may not exceed the budget its entry records.
    budget = cfg.get("unresolved_budget")
    over = budget is not None and unresolved > budget
    if unresolved and (verbose or over):
        for dotted in unresolved_names:
            print(f"  UNRESOLVED {name}: {dotted} (no candidate kernel name)")
    if over:
        print(
            f"  BUDGET {name}: {unresolved} unresolved, budget {budget}. Either the kernel "
            f"spells these differently again (teach `candidate_names`) or they are genuinely "
            f"not kernel constants (raise the budget, and say why)."
        )
    return ("skip" if len(zig) == 0 else ("fail" if over else "ok")), matched, mismatched, unresolved


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("modules", nargs="*", help="restrict to these module names (default: all registered)")
    ap.add_argument("--verbose", action="store_true", help="also print every MATCHED constant")
    args = ap.parse_args()

    names = args.modules or sorted(MODULES)
    unknown = [n for n in names if n not in MODULES]
    if unknown:
        print(f"unknown module(s): {unknown}; registered: {sorted(MODULES)}", file=sys.stderr)
        return 2

    total_mismatch = 0
    over_budget = 0
    for n in names:
        status, _, mismatched, _ = check_module(n, MODULES[n], args.verbose)
        total_mismatch += mismatched
        # An over-budget module is a FAILURE, not a note. The whole point of
        # the budget is that "unresolved" stopped being a number nobody reads.
        if status == "fail":
            over_budget += 1

    return 1 if (total_mismatch or over_budget) else 0


if __name__ == "__main__":
    sys.exit(main())
