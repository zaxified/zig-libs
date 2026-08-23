// SPDX-License-Identifier: MIT
//! tabular — dataset algebra: map/aggregate/pivot/resample/sort/topN (T0, in
//! `transforms`) and series ops cumsum/rolling/drawdown/join/... (T1, in
//! `series`) over `dataset`.
//!
//! The two tiers live in separate namespaces because their spec type names
//! collide (e.g. both would define their own `ColSpec`-shaped structs) and
//! flattening would be lossy. Reach a verb via its tier:
//! `tabular.transforms.aggregate(...)`, `tabular.series.rolling(...)`.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Dataset algebra (pandas/dplyr-style verbs) over `dataset` — aggregate/pivot/resample/rolling/join, fx-aware.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "pandas/dplyr verb algebra + TA rolling-window idioms",
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

// Dark-tests aggregator: a bare `pub const` re-export does NOT pull a
// submodule's tests into the test binary — this reference does.
test {
    _ = transforms;
    _ = series;
}
