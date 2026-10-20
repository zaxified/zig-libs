# mpdec_bench

Reference side of `zig build bench-decimal` (`../bench.zig`): libmpdec 4.0.1
(BSD-2, the C engine of Python's `decimal`) driven through its public API by
`driver.c`, which times itself like the Zig side (see its header). `bench.zig`
compiles the driver with `cc -O2 -g -std=gnu11` against a static libmpdec that
you build once, from source, inside the gitignored cache:

```sh
cd .zig-cache/bench-decimal
curl -LO https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-4.0.1.tar.gz
sha256sum mpdecimal-4.0.1.tar.gz   # 96d33abb4bb0070c7be0fed4246cd38416188325f820468214471938545b1ac8
mkdir -p src && tar -xzf mpdecimal-4.0.1.tar.gz -C src
cd src/mpdecimal-4.0.1
CFLAGS="-O2 -g" ./configure --disable-shared --disable-cxx
make -C libmpdec libmpdec.a        # => libmpdec/libmpdec.a, libmpdec/mpdecimal.h
```

The sha256 is the one on https://www.bytereef.org/mpdecimal/download.html
(checked 2026-10-20). configure/make only; nothing else is run.
`mpd_init` prints a harmless "ignoring request to set MPD_MINALLOC a second
time" warning per extra context on stderr.
