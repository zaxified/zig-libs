# `uci` verification instruments

Seven instruments, run by hand. None is wired into `zig build`: five of them
(`oracle_dump.c`, `classify.sh`, `diff_run.sh`, `diff_fuzz.py`,
`capture-grammar.sh`) need the real **`libuci`**, built from source and used as
a black-box oracle.
`zig build test-uci` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-17 against the tree as it stands.

## The structural differential against the real `libuci`

| tool | question it answers |
|---|---|
| `oracle_dump.c` | What model does the REAL `libuci` build from this text? Dumps sections/options as hex, so quoting can never be confused with content. |
| `module_dump.zig` | The same dump from this module, reading text on **stdin**. |
| `gen_probes.py` | 65 hand-written grammar probes, one per documented rule. |
| `classify.sh` | Runs both and **classifies** each: SAME / both reject / fail-open / fail-closed / same shape different bytes. |
| `diff_run.sh` | The same without classification, printing raw differences. |
| `diff_fuzz.py` | Random differential; `--valid` keeps statement shape legal so the parser is actually reached. |
| `capture-grammar.sh` | Captures the frozen `uci` grammar fixtures the suite pins. |

Measured over the 65 probes: **37 SAME · 23 BOTH-REJECT · 2 fail-open ·
3 deliberate strictness · 0 VALUE-DIVERGE.**

That last zero is the load-bearing one: wherever both implementations accept a
probe, they build the **same model, byte for byte**. The five non-SAME rows are
all recorded contract, not drift:

- **fail-open** (`n08_key_empty`, `n09_type_empty`) — the module accepts an
  empty key/type where `libuci` reports *insufficient arguments*. This is the
  audit's U18 path, pinned by `writeWord's empty-word path round-trips an empty
  type and an empty key`.
- **deliberate strictness** (`s01_dup_named_section` → `DuplicateSection`,
  `s05_option_then_list` / `s06_list_then_option` → `MixedOptionList`) — the
  module refuses three inputs `libuci` accepts. U1 and U11/U12; refusing is the
  chosen behaviour.

⚠ `oracle_dump.c` is ours (SPDX MIT) and links a `libuci` built locally from
OpenWRT source. Nothing copyleft travels with this repository — the reference
tree is fetched by the recipe below into a droppable cache, exactly the
precedent set by `modules/hqc/tools/oracle_hqc.c`.

### Building the reference oracle

```bash
BASE=<repo>/.zig-cache/uci-differential           # droppable; rebuilt by this recipe
mkdir -p "$BASE"/{ref,out,probes}
cd "$BASE/ref" && git clone --depth 1 https://git.openwrt.org/project/uci.git uci
cd uci && printf '/* audit */\n' > uci_config.h
gcc -O1 -std=gnu99 -I. -DUCI_PREFIX='"'"$BASE/ref/root"'"' \
    -o "$BASE/out/oracle_dump" <repo>/modules/uci/tools/oracle_dump.c \
    libuci.c file.c util.c delta.c parse.c
```

`diff_run.sh` and `classify.sh` derive `BASE` from their own location, so they
need no editing to run from a checkout anywhere.
