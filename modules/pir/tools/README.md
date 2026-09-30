# `pir` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `rederive.py` | `src/kat_vectors.zig` — `python3 modules/pir/tools/rederive.py > modules/pir/src/kat_vectors.zig` | Python 3, standard library only |

`rederive.py` is an independent re-derivation of the two-server DPF PIR (BGI16 Gen/Eval over the SHA-256 PRG, the server inner product in `Z_{2^{8L}}`, the client's word-wise sum), written from `modules/fss/SPEC.md` and `modules/pir/SPEC.md`. It first reproduces every vector of `modules/fss/src/kat_vectors.zig`; `python3 modules/pir/tools/rederive.py --self-check` runs just that step. Regenerating must be byte-identical to the committed file:

    python3 modules/pir/tools/rederive.py | diff - modules/pir/src/kat_vectors.zig

The script header states which facts came from the SPECs and which byte layouts came from the Zig source.
