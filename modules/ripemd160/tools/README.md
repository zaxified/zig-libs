# `ripemd160` verification instruments

Four instruments and one shared helper (`out.zig`), run by hand. None is wired
into `zig build`: `oracle_sweep.py` needs a **foreign toolchain** (Python
`hashlib` with ripemd160 and the `openssl` CLI), `bigsweep` writes ~59 MB of
blobs.
`zig build test-ripemd160` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-17 against the tree as it stands.

## Where the module's constants come from

`src/root.zig`'s KATs are individual digests, and a constant inherits whatever
mistake produced it. These are how those numbers can be **re-derived** rather
than re-read.

| tool | question it answers |
|---|---|
| `sweep.zig` | What does the module return for **every** length 0..1024? |
| `oracle_sweep.py` | Do Python `hashlib` and `openssl` agree, counted **separately**? |
| `bigsweep.zig` | Do the multi-megabyte sizes agree, one-shot vs streamed vs external? |
| `filehash.zig` | Does the module agree with `openssl` on bytes **somebody else** chose? |

Measured today:

- **Oracle sweep: 1025 lengths, 3 075 comparisons, 0 mismatches**, and `openssl`
  returned **1025 of 1025** digests. That last number is reported on purpose —
  an oracle that silently returned nothing would otherwise look like a clean
  run, so the script exits non-zero if the counts disagree.
- **Multi-megabyte: 12 blobs (59 MB), 36 external comparisons, 0 mismatches**,
  and one-shot equals streamed on all 12.
- **Exhaustive split differential: 3 178 512 comparisons, 0 mismatches**
  (180 901 two-way + 2 997 411 three-way + 200 fixed-chunk). The module's fuzz
  target walks the splits its input picks; this walks every split there is.
- **All four optimize modes are byte-identical**: the 1025-length sweep built in
  Debug, ReleaseSafe, ReleaseFast and ReleaseSmall produces the same 1025 lines,
  `sha256 576cbe15…`, in all four.

⚠ Both oracles are kept and counted separately even though `hashlib`'s
ripemd160 is itself usually OpenSSL-backed — "two oracles" that share a backend
are one witness wearing two hats, and that should be visible rather than
assumed away.
