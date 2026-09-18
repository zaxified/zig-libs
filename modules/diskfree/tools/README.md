# `diskfree` tools

One instrument, run by hand and never wired into `zig build`: it needs mount privilege
in a namespace, which `zig build test-diskfree` must not require (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runner and probes were deleted on 2026-09-18.

| file | produces | needs |
|---|---|---|
| `hostile-ns.sh` | real kernel `/proc/self/mounts` and `/proc/self/mountinfo` output for a namespace with hostile mount points, plus a `findmnt --json` cross-check, to anchor the `mounts.zig`/`mountinfo.zig` parsers against | `unshare -Ur -m`, `findmnt` |

```bash
unshare -Ur -m modules/diskfree/tools/hostile-ns.sh [output-dir]
```
