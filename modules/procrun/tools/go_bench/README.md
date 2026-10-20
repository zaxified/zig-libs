# go_bench

Go side of `zig build bench-procrun` (`../bench.zig`): Go `os/exec` (standard
library only; no `go.sum`, nothing to download) on the same child commands as
the Zig side. `bench.zig` builds it offline (`GOPROXY=off`) into
`.zig-cache/bench-procrun/go_bench`. The workloads and how each side runs them
are in the header of `main.go` and `../bench.zig`. Not a test and not part of
any lane.
