# `diskfree` tools

Four files, run by hand and never wired into `zig build`: `hostile-ns.sh` needs mount
privilege in a namespace and the `df` instruments need GNU coreutils, neither of which
`zig build test-diskfree` may require (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runner and probes were deleted on 2026-09-18.

| file | produces | needs |
|---|---|---|
| `hostile-ns.sh` | real kernel `/proc/self/mounts` and `/proc/self/mountinfo` output for a namespace with hostile mount points, plus a `findmnt --json` cross-check, to anchor the `mounts.zig`/`mountinfo.zig` parsers against | `unshare -Ur -m`, `findmnt` |
| `df-diff.sh` + `df_dump.zig` | the live differential against GNU `df`: module vs `df -B1 --output=…`, one `df` call per mount, verdict SAME / DRIFT / DIFF / SKIP per mount; exit 1 on any DIFF | GNU `df` (coreutils ≥ 8.21), `zig` |
| `capture-df-golden.sh` | `src/testdata/df_golden.txt`: raw statfs numbers + `df`'s columns per mount, captured until stable — the golden the suite replays | GNU `df`, `stat -f` |

```bash
unshare -Ur -m modules/diskfree/tools/hostile-ns.sh [output-dir]
```

```bash
modules/diskfree/tools/df-diff.sh                     # every mount; or give paths
modules/diskfree/tools/capture-df-golden.sh / /boot/efi /tmp … > modules/diskfree/src/testdata/df_golden.txt
```
