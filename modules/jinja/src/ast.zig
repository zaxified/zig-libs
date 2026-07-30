// SPDX-License-Identifier: MIT
//! The syntax tree the parser produces and the renderer walks. Everything is
//! arena-allocated and immutable once built, so a compiled `Template` is
//! shareable across threads and reusable across renders.

const std = @import("std");
const value = @import("value.zig");

pub const Value = value.Value;
pub const BinOp = value.BinOp;
pub const CmpOp = value.CmpOp;

pub const Kwarg = struct {
    name: []const u8,
    value: *const Expr,
};

pub const Args = struct {
    positional: []const *const Expr = &.{},
    keyword: []const Kwarg = &.{},
};

pub const DictEntry = struct {
    key: *const Expr,
    value: *const Expr,
};

pub const CompareLink = struct {
    op: CmpOp,
    right: *const Expr,
};

pub const Expr = union(enum) {
    literal: Value,
    /// A bare name, resolved against the context chain.
    name: []const u8,
    list: []const *const Expr,
    tuple: []const *const Expr,
    dict: []const DictEntry,
    getattr: struct { obj: *const Expr, name: []const u8 },
    getitem: struct { obj: *const Expr, index: *const Expr },
    slice: struct {
        obj: *const Expr,
        start: ?*const Expr,
        stop: ?*const Expr,
        step: ?*const Expr,
    },
    binop: struct { op: BinOp, lhs: *const Expr, rhs: *const Expr },
    neg: *const Expr,
    pos: *const Expr,
    not: *const Expr,
    /// Python-style chained comparison: `1 < x < 10` is one node.
    compare: struct { first: *const Expr, links: []const CompareLink },
    logical: struct { op: enum { @"and", @"or" }, lhs: *const Expr, rhs: *const Expr },
    cond: struct { then: *const Expr, cond: *const Expr, otherwise: ?*const Expr },
    filter: struct { input: *const Expr, name: []const u8, args: Args, line: usize },
    do_test: struct { input: *const Expr, name: []const u8, args: Args, negated: bool, line: usize },
    call: struct { callee: *const Expr, args: Args, line: usize },
    /// `a.b(…)` / `'x'.upper()` — dispatched as a method rather than as a call
    /// of an attribute value, because the receiver is what selects it.
    method: struct { obj: *const Expr, name: []const u8, args: Args, line: usize },
};

pub const Target = union(enum) {
    /// `{% set x = … %}`
    name: []const u8,
    /// `{% set a, b = … %}` — also the `{% for a, b in … %}` form.
    tuple: []const []const u8,
    /// `{% set ns.x = … %}`
    attr: struct { object: []const u8, name: []const u8 },
};

pub const If = struct {
    cond: *const Expr,
    body: []const Node,
    /// `{% elif %}` chains are desugared into a nested `if` in `orelse`.
    orelse_: []const Node,
};

pub const For = struct {
    target: Target,
    iterable: *const Expr,
    /// `{% for x in xs if cond %}` — applied before `loop.length` is computed.
    cond: ?*const Expr,
    body: []const Node,
    /// `{% else %}`, rendered when the *filtered* sequence is empty.
    empty: []const Node,
    recursive: bool,
};

pub const Set = struct {
    target: Target,
    expr: *const Expr,
};

pub const SetBlock = struct {
    target: Target,
    body: []const Node,
    /// `{% set x | filter %}…{% endset %}`
    filter: ?*const Expr,
};

pub const FilterBlock = struct {
    /// A filter chain applied to the rendered body; the innermost input is a
    /// placeholder the renderer substitutes.
    filter: *const Expr,
    body: []const Node,
};

pub const With = struct {
    assignments: []const Set,
    body: []const Node,
};

pub const Node = union(enum) {
    text: []const u8,
    output: struct { expr: *const Expr, line: usize },
    if_: If,
    for_: For,
    set: Set,
    set_block: SetBlock,
    filter_block: FilterBlock,
    with: With,
    /// `{% do expr %}` — evaluate for effect, emit nothing.
    do: struct { expr: *const Expr, line: usize },
};

/// The placeholder `Expr` a `{% filter %}` block's chain is applied to.
pub const filter_block_input: Expr = .{ .name = "\x00filter_block_input" };
