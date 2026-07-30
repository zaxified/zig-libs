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

/// A macro parameter: a name and, optionally, a default expression evaluated
/// at call time in the macro's own scope.
pub const Param = struct {
    name: []const u8,
    default: ?*const Expr = null,
};

/// A `{% macro %}` definition, and also the synthetic macro a `{% call %}`
/// block's body becomes so that `caller()` can invoke it.
pub const MacroDef = struct {
    name: []const u8,
    params: []const Param,
    body: []const Node,
    /// Whether the body mentions these special names. The reference decides
    /// statically whether a macro will *accept* extra positional/keyword
    /// arguments, so this has to be known at parse time, not at call time.
    catch_varargs: bool = false,
    catch_kwargs: bool = false,
    uses_caller: bool = false,
    line: usize = 0,
};

/// A `{% block %}` body, stored in the template's block table. The `Node` that
/// marks the block's *position* carries only the name — which definition runs
/// is a property of the inheritance chain, not of the node.
pub const BlockDef = struct {
    name: []const u8,
    body: []const Node,
    /// `{% block x scoped %}` — the body can see the enclosing loop's
    /// variables. Without it a block sees only template-level names.
    scoped: bool = false,
    /// `{% block x required %}` — a derived template must override it.
    required: bool = false,
    line: usize = 0,
};

pub const Include = struct {
    /// A single name or a list of candidates; the first that loads wins.
    names: *const Expr,
    ignore_missing: bool,
    /// `{% include %}` defaults to **with** context.
    with_context: bool,
    line: usize,
};

pub const Import = struct {
    name: *const Expr,
    /// `{% import 'm' as target %}`
    target: []const u8,
    /// `{% import %}` defaults to **without** context — the opposite of
    /// `{% include %}`.
    with_context: bool,
    line: usize,
};

pub const FromImport = struct {
    pub const Alias = struct { name: []const u8, as: []const u8 };

    template: *const Expr,
    names: []const Alias,
    with_context: bool,
    line: usize,
};

pub const CallBlock = struct {
    /// The macro invocation the body is handed to.
    call: *const Expr,
    /// `{% call(a, b) m() %}` — the parameters `caller()` is invoked with.
    caller: MacroDef,
    line: usize,
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
    /// `{% extends expr %}` — records the parent; the renderer builds the
    /// chain before any output is produced.
    extends: struct { name: *const Expr, line: usize },
    /// The *position* of a block in this template. The body lives in the
    /// template's block table so the chain can override it.
    block: struct { name: []const u8, line: usize },
    include: Include,
    import: Import,
    from_import: FromImport,
    macro: struct { def: *const MacroDef, line: usize },
    call_block: CallBlock,
};

/// What `parser.parse` produces for one template.
pub const Parsed = struct {
    nodes: []const Node,
    /// Every `{% block %}` in the template, wherever it is nested.
    blocks: []const BlockDef,
    /// The `{% extends %}` name expression, when the template has one.
    extends: ?*const Expr = null,
};

/// The placeholder `Expr` a `{% filter %}` block's chain is applied to.
pub const filter_block_input: Expr = .{ .name = "\x00filter_block_input" };
