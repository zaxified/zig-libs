# `df-elect` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

| path | produces | needs |
|---|---|---|
| `rederive.py` | `src/kat_vectors.zig` — `python3 modules/df-elect/tools/rederive.py > modules/df-elect/src/kat_vectors.zig`; an independent re-derivation of RFC 7432 §8.5 (mod N) and RFC 8584 §3.2 (HRW, CRC-32 via `zlib`) | Python 3, stdlib only |
| `frr/` | black-box observations of FRRouting's EVPN multihoming DF election (see `frr/README.md`) | rootless podman, the pinned FRR image |
