# `qrscan` verification instruments

Three instruments, run by hand. None is wired into `zig build`: all need a
**foreign toolchain** (Python + zxing-cpp, Pillow, segno; a venv, since zxing-cpp
is not installed system-wide). `zig build test-qrscan` must require none of it
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. **Not adopted:** the audit's `probe.zig` (`p1`/`p1small`/`p1zero`,
`p2`/`p2scale`/`p2big`, `p3`/`p3sweep`, `p4`) — every one of those is a per-finding
probe or a benchmark of a since-fixed regression (F1 CRITICAL stride-overread, F2 HIGH
quadratic scan cost, F4 DOC unlabelled-finder fallback; all closed, see the module's
`CHANGELOG.md`), the two kinds `CONVENTIONS.md` §9 explicitly excludes. It anchors on
source text (line numbers, internal field names) that the fixes already moved.

Figures below were measured on 2026-09-17 against the tree as it stands.

## Does an independent decoder read the same symbols?

| tool | question it answers |
|---|---|
| `gen2.py` | Generates 37 flat/rotated/degraded images (segno, BSD-3-Clause + Pillow, MIT-CMU): v1-v22, 3-10 px/module, rotation 5-77°, blur, illumination gradient, σ=40 noise. |
| `gen3.py` | Generates 24 perspective images: v1/v4/v15, tilt 0-40° about the vertical axis, 6 px/module. |
| `oracle.py` | Runs **zxing-cpp** (Apache-2.0) over a corpus and diffs its verdict against `qrscan-demo` (`modules/qrscan/example/main.zig`, itself built only against `@import("qrscan")`/`@import("qr")`). ZXing is *run*, never read; ZBar (LGPL) is not used. |

The images are **not** committed (regenerate in seconds, ~20 MB) — only the recipe is,
per `CONVENTIONS.md` §9: an anchor nobody can re-take is an assertion, not evidence.

```bash
# one-time: a venv, since zxing-cpp isn't installed system-wide
python3 -m venv .zig-cache/o1-qrscan/venv
.zig-cache/o1-qrscan/venv/bin/pip install zxing-cpp pillow segno numpy

# the module's own example CLI, built against its published API only
scripts/lib/capped zig build-exe --cache-dir <scratch>/zc -OReleaseFast \
  -femit-bin=<scratch>/qrscan-demo \
  --dep qrscan --dep qr -Mmain=modules/qrscan/example/main.zig \
  --dep qr -Mqrscan=modules/qrscan/src/root.zig \
  -Mqr=modules/qr/src/root.zig

cd <scratch> && <repo>/.zig-cache/o1-qrscan/venv/bin/python3 <repo>/modules/qrscan/tools/gen2.py corpus2
<repo>/.zig-cache/o1-qrscan/venv/bin/python3 <repo>/modules/qrscan/tools/gen3.py corpus3
<repo>/.zig-cache/o1-qrscan/venv/bin/python3 <repo>/modules/qrscan/tools/oracle.py <scratch>/qrscan-demo corpus2 corpus3
```

**Measured 2026-09-17:**

- **Flat / rotated / degraded (37 images):** ZXing 33/37, qrscan 33/37 — **identical
  verdicts on every single image**. The 4 mutual misses are all the same perspective
  case (`persp_10`..`persp_40`) that both decoders reject; the audit traced this to a
  bad quad transform in `gen2.py`'s generator, not a module defect.
- **Perspective (24 images):** ZXing 24/24, qrscan 19/24. The 5 qrscan misses are all
  ≥30°: `v1_t30`, `v1_t40`, `v6_t40`, `v13_t30`, `v13_t40` — one `no QR symbol
  located`, the rest `found ... but its Reed-Solomon blocks carry more damage than its
  level can repair` (the module locates the symbol and declines rather than guessing).
  qrscan holds to 25° at v1/v15 and 30° at v4 — **better than the SPEC's own backlog
  note suggested**, so this is a conservative, not a false, limit.
- **Total: ZXing 57/61, qrscan 52/61.** Both figures match the original audit run
  exactly (37/37 and 24/24 case counts, same 4+5 misses).

**Licences, verified at the installed package's own metadata (`pip show <pkg>`):**
zxing-cpp 3.1.1 → `License-Expression: Apache-2.0` (Apache License 2.0 text also
shipped under the wheel's `licenses/` directory); segno 1.6.6 → BSD License
(classifier); Pillow 12.3.0 → `License-Expression: MIT-CMU`. All permissive, no
copyleft obligation. ZBar (LGPL) is never installed or invoked by anything here.
