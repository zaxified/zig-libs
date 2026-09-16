# `uci` verification instruments

Eleven instruments, run by hand. None is wired into `zig build`: five of them
(`oracle_dump.c`, `classify.sh`, `diff_run.sh`, `diff_fuzz.py`,
`capture-grammar.sh`) need the real **`libuci`**, built from source and used as
a black-box oracle, and the mutation runner costs minutes per row.
`zig build test-uci` must require none of it (`CONVENTIONS.md` §9).

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

## Would the suite notice if a guard were removed?

    modules/uci/tools/mutate.py               # the whole table
    modules/uci/tools/mutate.py --only quote  # rows whose name contains "quote"
    modules/uci/tools/mutate.py --controls    # only the positive controls

30 mutations and 2 positive controls, each copying the live
`modules/uci/src/` into a per-process scratch tree.

Measured: **32 rows, 27 RED, 5 GREEN, 0 BROKEN, 0 anchor problems.** Every
verdict is pinned in the table and the runner reports a mismatch rather than
quietly accepting a new answer. The five survivors:

| mutant | guard the suite does not notice |
|---|---|
| `weak_unserializable_allows_newline` | `isEscapelessControl` widened by `0x0b` (vertical tab) |
| `weak_baresafe_allows_hash` | `isBareSafe` widened by `#` |
| `weak_baresafe_allows_space` | `isBareSafe` widened by a space |
| `weak_empty_name_stays_named` | `.anonymous` forced false for an unnamed section |
| `weak_nth_upper_bound_only` | `nth`'s negative-index lower bound |

### Three anchors whose mutation did not COMPILE, and why that is not a verdict

A mutant that fails to build scored `BROKEN`, never `RED`: nothing ran, so
calling it "the suite noticed" would claim a result that was never measured.
Three rows had to be re-derived for this reason, all of them defects in *this
runner*, not in the module:

- **`del_too_many_args_config`** used `else => return,`. `endStatement` returns
  `ParseError!bool`, so a bare `return` is void. It now swallows the rest of the
  line and returns `false` — and it must consume the input, or the caller
  re-reads the same byte forever instead of failing a test.
- **`del_unserializable_value`** used `if (false)`, leaving the loop capture `c`
  unused. It now **spends** the value (`c != c`), the cure proven on `s7comm`'s
  `D2`.
- **`weak_section_ignores_type`** dropped the type comparison, leaving the
  *parameter* `section_type` unused. It now spends it
  (`section_type.len != section_type.len or …`), which ignores the type — the
  mutation — while still building.

### And the command line rots separately from the anchors

The audit's runner drove a bare `zig test root.zig`. Measured today that fails
at `root.zig:1921` with `no module named 'testkit'`; with `--dep testkit` the
same suite is `53/53, rc=0`. A dry run cannot see this — 19 of its 33 anchors
still matched their site exactly once. **13 anchors had rotted** besides: the
U5/U6 tokenizer rewrite and the U8/U9/U10/U17/U19 batch grew `root.zig` from
1452 to 2621 lines, so the old texts named code that no longer exists.

## Cost, memory and the round-trip asymmetry

| tool | question it answers |
|---|---|
| `perf_probe.zig` | Is `addOption` quadratic, and how many arena bytes does an input byte buy — as **peak live bytes**, not a cumulative counter? |
| `roundtrip_stress.zig` | Does the model survive serialize→parse, and is everything `parse` accepts something `serialize` can emit? |
| `ser_probe.zig` | Text → `parse` → `serialize` → stdout, so the output can be handed to the **real** `libuci` and checked for loadability. |

`perf_probe` is the only way to re-derive the numbers `max_total_items`' doc
comment asserts (22×–41.5× amplification, "a 16 MiB file could legally cost
371+ MB of RSS"). No test pins peak memory — `total item cap: boundary is
exact` pins the item COUNT, which is the guard, not the consequence it was
chosen for. Measured today: **34.7×–46.1×** across `distinct_key` and
`one_per_section` at n=1000..16000, and 400 000 sections is refused with
`MemoryLimitExceeded` rather than allocated.

The audit kept three further copies of `perf_probe` (`perf_cap`, `perf_cap2`,
`perf_quad`) differing from it in exactly one thing — the size/mode table,
edited in place. They are one instrument with arguments, and that is what this
now is; the sweep is argv.

⚠ **`roundtrip_stress`'s headline number is documented behaviour, not a
defect.** 200 000 models: 145 778 correctly refused as unserializable, 0
mismatches, and **48 516 that serialize and then fail to re-parse — all 48 516
with `InvalidName`**. That is the U7/U14 interaction, and it is deliberate:
`serialize` does not validate the option KEY, `parse` does, so a hand-built
model whose key contains `'`, a space or `.` is written safely **quoted** and
is then refused on the way back in. The test `isBareSafe boundary: a key
containing a quote character must not be written bare` states exactly this and
asserts the `InvalidName` itself. What the probe adds is the proportion: about
a quarter of random models cannot survive a text round trip.

⚠ **One stale claim found while measuring it.** `serialize`'s comment (at the
`validTypeChars` call) says the option key is not checked because *"audit A1
U14 already guarantees it round-trips safely either way"*. The U14 test it
cites says the opposite in its own words — the key "can no longer round-trip
through TEXT, only survive as an in-memory model". The behaviour is right and
tested; the sentence describing it is not.

Direction **B** is why `roundtrip_stress` came over rather than being scored
spent: the module has exactly two fuzz targets and both walk from a model
outward. Nothing in the suite asks whether text the parser accepted can be
written back out — the read-modify-write path a config tool actually performs.
Measured: 75 879 parsed, **0 not serializable**.

## What was deliberately not brought over

`.zig-cache/audit-uci` was 380 MB: a full reference checkout, compiled
artefacts, mutant trees and nine probe sources.

- `accessor_probe.zig` — **spent**. Its finding (U13: four name comparisons
  weakenable to a prefix, suite stayed green) is now pinned by
  `accessors distinguish prefix-related names, not just a shared prefix`, which
  names U13 and covers all four sites.
- `smith/root.zig` — **spent**. The `Smith.bytes` + ranged-draw trap (U15) is
  fixed in `src/`: one byte-first `smith.slice` draw, plus a 15-entry corpus and
  a test that pins what each seed builds.
- `perf_cap.zig`, `perf_cap2.zig`, `perf_quad.zig` — folded into
  `perf_probe.zig`'s arguments, as above.
