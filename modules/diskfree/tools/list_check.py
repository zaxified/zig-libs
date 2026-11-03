#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Listing verdict for df-where-diff.sh: list_check.py LABEL MODULE_LIST DF_LIST

Both lists are mount points, one per line. Prints one summary line and exits 1 when
  * df lists a mount the module does not (a parity gap), or
  * the module lists a mount df does not AND that mount's device number
    (major:minor, /proc/self/mountinfo) is not shared with a mount df lists
    (df shows a device once, so a bind mount of a listed filesystem is the one
    legitimate module-only row).
"""
import sys

label, mod_f, df_f = sys.argv[1:4]
mod = {x for x in open(mod_f).read().split("\n") if x}
dfl = {x for x in open(df_f).read().split("\n") if x}
dev = {}
for line in open("/proc/self/mountinfo"):
    f = line.split(" ")
    dev[f[4].encode().decode("unicode_escape")] = f[2]
listed_devs = {dev.get(m) for m in dfl}
only_df = sorted(dfl - mod)
only_mod = sorted(mod - dfl)
repeated = [m for m in only_mod if dev.get(m) in listed_devs]
unexplained = [m for m in only_mod if dev.get(m) not in listed_devs]
print(f"list[{label}]: {len(dfl)} df rows, {len(mod)} module rows; df-only {only_df or 'none'}; "
      f"module-only {len(only_mod)} = {len(repeated)} repeated-device + {len(unexplained)} UNEXPLAINED {unexplained or ''}")
sys.exit(1 if only_df or unexplained else 0)
