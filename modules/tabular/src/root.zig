// SPDX-License-Identifier: MIT
//! tabular — dataset algebra: map/aggregate/pivot/resample/sort/topN (T0, in
//! `transforms`) and series ops cumsum/rolling/drawdown/join/... (T1, in
//! `series`) over `dataset`, row expressions (`expr`) and window functions per group
//! (`window`).
//!
//! The two tiers live in separate namespaces because their spec type names
//! collide (e.g. both would define their own `ColSpec`-shaped structs) and
//! flattening would be lossy. Reach a verb via its tier:
//! `tabular.transforms.aggregate(...)`, `tabular.series.rolling(...)`.
//!
//! Memory: every verb takes an allocator, assumed to be an arena. Temporaries are freed,
//! but a result has no `deinit`. Results borrow from the input and the spec: many share
//! the input's rows (`filter`, `sort`, `page`, `distinct`, ...), all share its text bytes
//! and column names. Keep input and spec alive as long as the result.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Dataset algebra (pandas/polars-style verbs) over `dataset` — aggregate/pivot/join/window/expressions, fx-aware.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "pandas/polars/dplyr verb algebra + TA rolling-window idioms",
    .deps = .{"dataset"},
};

// ── public API ──────────────────────────────────────────────────────────────

/// Tier 0 — pure `dataset → dataset` primitives: map · aggregate(+fx) ·
/// weightedGroupSum(+fx) · percentOfTotal · sort(multi-key) · topN · page ·
/// pivot(numeric-aware) · unpivot · resample · reduce · clampRange ·
/// format/formatColumn.
pub const transforms = @import("transforms.zig");

/// Tier 1 — series math over a date-ordered dataset: cumsum · cumreturn ·
/// drawdown · rolling · pctChange · rebase · forwardFill · outlierFlag ·
/// mergeByKey · distinct · datePart · join(inner/left/right/full/semi/anti,
/// single- or composite-key) · stdSample.
pub const series = @import("series.zig");

/// Row expressions: `mutate` · `where` (nested predicates, column vs column, IN,
/// when/then, coalesce, math, text) · `cast` (the coercion rules in one place).
pub const expr = @import("expr.zig");

/// `window.window`: shift · diff · pct_change · cumulative · rolling (count- and
/// time-based) · expanding · ewm · rank · ffill/bfill · interpolate · transform, each
/// optionally per group.
pub const window = @import("window.zig");

// Dark-tests aggregator: a bare `pub const` re-export does NOT pull a
// submodule's tests into the test binary — this reference does.
test {
    _ = transforms;
    _ = series;
    _ = @import("keys.zig");
    _ = @import("oracle_test.zig");
    _ = @import("review_test.zig");
    _ = expr;
    _ = window;
    _ = @import("sweep_test.zig");
}
