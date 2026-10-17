# `b64ct` verification instruments

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-b64ct`: live differential oracle against libsodium 1.0.22's `sodium_bin2base64`/`sodium_base642bin` — 300 000 cases from a fixed seed (encode, whole decode with and without an ignore set, prefix decode), exit 0 only when every verdict, octet and prefix length agrees. Its header lists what it needs. |
| `sodium_oracle.c` | The libsodium side of `interop.zig`: one case per line in, one verdict per line out. |
| `bench.zig` + `c_bench/sodium_bench.c` | `zig build bench-b64ct`: comparative benchmark against the same libsodium, sides alternating, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). |
| `sodium_shim/` | Three small headers (`core.h`, `utils.h`, `private/common.h`) that let libsodium's `codecs.c` compile on its own: `sodium_misuse` → `abort`, `ACQUIRE_FENCE` → nothing, the base64 constants and prototypes of its public `sodium/utils.h`. Ours, written from the documented API. |

## The foreign reference: driven, not vendored

Both programs compile ONE file of libsodium — `src/libsodium/sodium/codecs.c`
at tag `1.0.22-RELEASE` — against `sodium_shim/`, instead of linking the
system library: Ubuntu 24.04 ships 1.0.18, whose decoder accepts every octet
0x80–0xff as sextet 63 (fixed upstream in a615d0ed, "base64: reject signed
chars", 2026-03-29). Fetch it into `.zig-cache/foreign/libsodium-1.0.22/`
(or point `SODIUM_CODECS_SRC` at a directory holding it) and read it before
compiling:

    mkdir -p .zig-cache/foreign/libsodium-1.0.22
    curl -fsSL -o .zig-cache/foreign/libsodium-1.0.22/codecs.c \
      https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22-RELEASE/src/libsodium/sodium/codecs.c
    sha256sum .zig-cache/foreign/libsodium-1.0.22/codecs.c
    # 77e675be30ecd8776e0924596bbf305cbc44f41d8df3238fd65c03aa99091b3e

Both programs refuse (exit 2, with this recipe) a file with another hash.
libsodium is ISC-licensed; the file is never committed here.
