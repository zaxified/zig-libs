# rust_bench (tlsserver alt side)

Alt side of `zig build bench-tlsserver`: a rustls 0.23.43 + aws-lc-rs 1.18.0
TLS 1.3 server doing the same server-side work as `../c_bench/foreign_bench.c`.
Read the header of `src/main.rs` for the method.

    rust_bench <work dir> <workload>   name \t ns/op \t user cycles/op \t count
    rust_bench <work dir> interop      every workload once, checked, stderr

Workloads: `hs_p256`, `hs_p256_mlkem`, `hs_rsa2048`, `resumed`, `send_16k`,
`recv_16k`. Differences from the C side: aws-lc cannot replay a recording, so
each handshake op is a fresh rustls client and server (only the server's calls
are timed); the server's connection drop is timed, as `SSL_free` is on the C
side.

`zig build bench-tlsserver` builds it. By hand, from the repository root
(offline, pinned by `Cargo.lock`; into the bench's own target directory, not a
`target/` here):

    CARGO_TARGET_DIR=.zig-cache/bench-tlsserver/target cargo build --release \
        --locked --offline --manifest-path modules/tlsserver/tools/rust_bench/Cargo.toml
