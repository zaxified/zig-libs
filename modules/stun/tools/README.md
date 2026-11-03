# `stun` verification instruments

| tool | role |
|---|---|
| `bench.zig` + `go_bench/` + `go_bench_gortc/` | `zig build bench-stun`: Binding-request encode, response decode with address and both checks, hostile-datagram rejects, against Go `github.com/pion/stun/v3` v3.1.6 (the reference) and `gortc.io/stun` v1.23.0 (the faster-on-two-rows Go candidate). Both Go programs are the same source with one import line changed. Needs go 1.26 and both modules (with pion's dependencies, pinned in `go_bench/go.sum`) in the module cache. Wire bytes and decoded results must agree with ours or the run refuses to report. |

No oracle server is kept: the RFC 5769 vectors and the two Go libraries' byte agreement in the bench are the interop evidence;
MESSAGE-INTEGRITY-SHA256 has no Go implementation and is checked against a golden computed by Python `hmac`.
