# `ethfrag` tools

One instrument, run by hand and never wired into `zig build`: it needs a Python
interpreter and `CAP_NET_RAW`, and `zig build test-ethfrag` must require neither
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's probes and mutation runner were deleted on 2026-09-17; what
they found is pinned by tests in `src/` or recorded in the module's changelog.

| file | produces | needs |
|---|---|---|
| `capture.py` | what the real Linux kernel's `ip_defrag` does with each fragment set, frozen into `src/kernel_oracle.zig` (audit F13) | Python 3, `CAP_NET_RAW` (an unprivileged user + net namespace is enough) |

```bash
# without the namespace every scenario SKIPs and the script exits 1
unshare --user --map-root-user --net -- sh -c \
    'ip link set lo up && python3 modules/ethfrag/tools/capture.py --verify'
```

The script's own header describes both entry points, how the fragments are built by
hand (no `scapy`) and how the kernel is used as the only judge of reassembly.
