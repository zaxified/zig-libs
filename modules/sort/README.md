# sort

Fast in-place sorting of slices: the sorts of Rust's standard library,
ported. `unstable` is ipnsort (Rust's `sort_unstable`) and has the exact
signature of `std.sort.pdq`, so a call site switches by name. `stable` is
driftsort (Rust's `sort`). `selectNth` is introselect (Rust's
`select_nth_unstable`, C++ `nth_element`), the tool for medians and
percentiles.

Why not std: `std.sort.pdq` partitions with branches the CPU cannot predict
on random input, and `std.sort.block` pays for in-place stability. On the
same keys the ported sorts run 2.4–4× faster than either, at parity with
Rust (numbers below).

- **Model after:** Rust `core::slice::sort` 1.93.1 (ipnsort and driftsort,
  Lukas Bergdoll and Orson Peters), ported. Given the same input it takes the
  same decisions as Rust (SPEC.md has the one place where it repeats a few
  comparisons).
- **Platform:** any, pure Zig, no OS dependency. **Role:** util.
  **Concurrency:** `reentrant`.
- **Deps:** none (`std` only; `testkit` for tests).

## Use

```zig
const sort = @import("sort");

// Unstable: same shape as std.sort.pdq (T, items, context, lessThan).
sort.unstable(u64, keys, {}, sort.asc(u64));
sort.unstable(Ip, addrs, {}, Ip.lessThan);

// Byte strings: sort.asc([]const u8) compares eight bytes at a time.
// std.mem.order walks byte by byte and costs ~1.7× here.
sort.unstable([]const u8, names, {}, sort.asc([]const u8));

// Stable: keeps equal elements in input order. Takes scratch from `gpa`
// like Rust does: none for ≤ 20 items or when it fits in 4 KiB of stack,
// else max(n - n/2, min(n, 8 MB / @sizeOf(T))) elements, freed on return.
try sort.stable(Row, gpa, rows, {}, Row.byDate);

// Stable without allocating: bring the scratch (at least stableScratchLen(n),
// not overlapping the items). More scratch, up to n, is faster on random input.
var scratch: [1000]Row = undefined;
sort.stableBuffer(Row, rows[0..1000], &scratch, {}, Row.byDate);

// The median, in O(n) and in place: v[mid] is the element a full sort would
// put there, smaller-or-equal ones before it, greater-or-equal ones after.
const mid = latencies.len / 2;
sort.selectNth(u32, latencies, mid, {}, sort.asc(u32));
const p50 = latencies[mid];
```

A context works like in std: `lessThan(context, a, b)`. To sort indices by
a key held elsewhere, pass the key array as the context.

### The comparator contract

`lessThan` must be a strict weak order: `lessThan(a, a)` is false, it is
transitive, and incomparability is transitive. A float `<` with NaNs in the
data is not one. A comparator that breaks the contract gets back an
unspecified **permutation** of its input: no element lost or duplicated, no
read or write outside the slice (and the scratch), in every build mode. It
still finishes in `O(n log n)` comparisons (`O(n²)` worst case for
`selectNth`, as in Rust). Rust panics in some of these cases; Zig cannot
unwind out of a sort, so this module returns instead.

### Complexity and memory

| | time | extra memory |
|---|---|---|
| `unstable` | `O(n log n)` worst; `O(n)` if sorted or strictly descending | none (≤ 4 KiB of stack) |
| `stable` | `O(n log n)` worst; `O(n)` on a few long sorted or strictly descending runs | `gpa`, see above |
| `stableBuffer` | same | the caller's scratch, ≥ `max(n - n/2, 48)` |
| `selectNth` | `O(n)` worst (honest comparator) | none |

## Performance

Ours ÷ theirs, lower is better (vs Rust by user-mode cycles, vs C++ by wall time) (`zig build bench-sort`,
2026-10-25, i7-7920HQ, JCC-mitigated builds — see `tools/README.md`):

| | vs Rust std 1.93.1 | vs C++ libstdc++ 15 |
|---|---|---|
| `unstable`, random `u64` 1k–1M | 0.97–1.00× | 0.28–0.62× |
| `unstable`, 4–24-byte strings (`asc([]const u8)`) | 0.91–0.93× | 0.41–0.48× |
| `stable`, random `u64` / 32-byte records | 0.97–1.02× / 0.99–1.00× | 0.34–0.35× / 0.70–0.77× |
| `stable`, strings | 0.55–0.63× | 0.54–0.60× |
| `selectNth` (median), random `u64` | 1.03–1.04× | 0.24–0.31× |
| sorted with a 1 % random tail (`unstable`) | 0.98× | 1.53× |
| ascending runs of 1 000 (`stable`) | 0.78× | 1.80× |

Against `std` (1 000 random elements, one-off probe): `u64` 7.1 µs vs
`std.sort.pdq` 26.9 µs and `std.sort.block` 17.3 µs; `netaddr.Ip` 25.7 µs vs
67.0 / 62.0 µs. Strings sort through `std.mem.order` 1.7× slower than
through `asc([]const u8)`.

## Verify

```sh
scripts/modtest sort                    # unit, model and reach tests
SORT_FUZZ=200000 zig build test-sort    # the deterministic fuzz driver
zig build run-example-sort              # the consumer example, leak-checked
zig build bench-sort                    # vs Rust std and C++ libstdc++ (cargo, g++)
```

Provenance: ported from the Rust standard library (MIT OR Apache-2.0, MIT
taken); the terms and the list of ported files are in [`NOTICE`](NOTICE).
