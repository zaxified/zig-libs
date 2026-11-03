# rawsock — tools

| tool | role |
|---|---|
| `interop.zig` | `unshare -rn zig build interop-rawsock [-- --capture]`: the Linux kernel as a live foreign peer over a veth pair — it must agree with `ifaceByName`/`ifaceName`/`hwaddr`/`ipv4Addr`/`ipv4Netmask` (set by `ip`) and must answer our `arp.buildRequest`; `--capture` refreshes `src/testdata/kernel_arp.zig`. Needs `ip`, no real root. |
| `gen_filter_oracle.py` | Recipe for the `corpus_pcap` and `oracle` blocks in `src/filter.zig`: asks `tcpdump -n -tt -r` (libpcap, black box) which frames each of 100 expressions selects. `python3 -I modules/rawsock/tools/gen_filter_oracle.py OUTDIR` from the repo root; reproduces the committed blocks byte for byte (2026-11-03). |
| `gen_pcapng_fixtures.py` | Recipe for the pcapng fixtures in `src/pcapng.zig`: `editcap -F pcapng` (Wireshark, black box) conversions and the writer's expected bytes, read back with `tcpdump` and `capinfos`. Same invocation; reproduces the committed fixtures byte for byte. |
| `bench.zig` + `c_bench.c` | `zig build bench-rawsock`: filter compile / run, pcap read / write, pcapng read against libpcap 1.10.6 (system `libpcap.so.0.8`, `LIBPCAP` overrides the path; needs `cc`). Run through `hw run`. |
