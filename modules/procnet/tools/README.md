# `procnet` tools

| tool | role |
|---|---|
| `bench.zig` + `go_bench/` | `zig build bench-procnet`: comparative benchmark against prometheus/procfs v0.21.1, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). Not run by any lane. |

## Benchmark

Each row reads THIS process's own /proc file and parses it, the same file on both sides, the
same number of times (read + parse; the syscalls are in the number on both sides). procfs
has no parse-from-bytes entry point (`Proc.Stat`, `Proc.Limits`, ... open the file
themselves and the parsers are unexported), so there are no `parse_*` rows.

| row | ours | procfs |
|---|---|---|
| `pid_stat` | `readPidStat(.self)` | `Proc.Stat()` |
| `pid_limits` | `readPidLimits(.self)` | `Proc.Limits()` |
| `pid_status` | `readPidStatus(.self)` | `Proc.NewStatus()` |
| `pid_io` | `readPidIo(.self)` | `Proc.IO()` |
| `fd_count` | `countFds(.self)` | `Proc.FileDescriptorsLen()` |
| `pid_netstat` | `readPidNetstat(.self)` | `Proc.Netstat()` |
| `net_unix` | `readUnix` | `FS.NetUNIX()` |
| `net_dev` | `readNetDev` | `FS.NetDev()` |
| `stat` | `readStat` | `FS.Stat()` |

The two sides are different processes, so utime / vsize / fd counts legitimately differ.
The result count is a loose invariant both compute identically (pid is this process and
state sane; the sum of every soft limit except `Max open files`, which the Go runtime
raises; uid/gid and tgid; fd count within 3..255; interface count and `lo`; CPU row count
and `btime` plausible; see the header of `bench.zig`). A count mismatch fails the run.

Results, 2026-10-17, x86-64 (provisional, `BENCH_ROUNDS=5`, ReleaseFast, ratios by wall time,
ours/procfs; the three-round run agrees within 0.05 on every row):

| row | ours ns | procfs ns | ratio |
|---|--:|--:|--:|
| `pid_stat` | 8831 | 24804 | 0.356 |
| `pid_limits` | 11907 | 42463 | 0.280 |
| `pid_status` | 15820 | 33957 | 0.466 |
| `pid_io` | 6388 | 16207 | 0.394 |
| `fd_count` | 1769 | 2040 | 0.867 |
| `pid_netstat` | 107137 | 127441 | 0.841 |
| `net_unix` | 1434423 | 1528594 | 0.938 |
| `net_dev` | 89311 | 98055 | 0.911 |
| `stat` | 23654 | 140152 | 0.169 |

Worst 0.94 (`net_unix`), best 0.17 (`stat`). Spread between rounds was 3-30 % (the run was
not on a quiet machine; `net_dev` 15 %, procfs `pid_limits` 30 %), so the rows near 1.0
(`net_unix`, `net_dev`, `fd_count`, `pid_netstat`) are within noise of each other's
neighbours but all stayed under 1.0 in both runs. `net_unix`, `net_dev`, `pid_netstat` and
`fd_count` are dominated by the kernel (seq_file generation / `stat` of `/proc/self/fd`),
which is why they sit near 1.

`card: **Performance:** ref 0.17–0.94× prometheus/procfs v0.21.1 · fastest ? (measured 2026-10-17)`

Not compared: gopsutil (the earlier card reference, not in the module cache), the
"fastest" reference, parse-only rows, other pids than self, aarch64.

procfs v0.21.1 facts checked before building: no cgo and no `unsafe` in any non-test
file; `syscall` appears in `fs_statfs_type.go` (the `/proc` filesystem-type check in
`NewFS`), `internal/util/sysreadfile.go` and some `sysfs` files. It reads files with
`os.Open`/`io.ReadAll`, parses with `fmt.Fscan`/`Sscanf`/regexp/`strings.Split`.

```bash
zig build bench-procnet                 # all rows (BENCH_ROUNDS=n, default 3)
zig build bench-procnet -- net_unix     # filter rows by substring
```

Needs a local `go` >= 1.26 with `github.com/prometheus/procfs v0.21.1`,
`golang.org/x/sys v0.47.0`, `golang.org/x/sync v0.22.0` and `github.com/google/go-cmp v0.7.0`
in its module cache; the driver sets `GOTOOLCHAIN=local GOPROXY=off`, so no network.
`go_bench/go.sum` pins them.
