// SPDX-License-Identifier: MIT
//! Chunks → `ast.Node` tree.
//!
//! The expression grammar is layered the way the reference's documented
//! precedence table is (condexpr → or → and → not → compare → math1 → concat →
//! math2 → pow → unary → primary → postfix → filter), because precedence is
//! observable: `-2 ** 2` and `not a == b` have to bind the way the reference
//! binds them, and the corpus pins each layer against it.
//!
//! Filter and test **names** are resolved here, against the environment's
//! registry, not at render time. A template naming a filter that does not exist
//! is a compile error — discovering that in production, mid-render, halfway
//! through a device configuration, is exactly the failure mode this module is
//! meant to prevent.

const std = @import("std");
const lex = @import("lexer.zig");
const ast = @import("ast.zig");
const value = @import("value.zig");

const Token = lex.Token;
const Expr = ast.Expr;
const Node = ast.Node;
const Value = value.Value;

pub const Error = error{ OutOfMemory, TemplateSyntaxError };
pub const Diagnostic = lex.Diagnostic;

/// How the parser asks the environment whether a filter/test name exists.
pub const Registry = struct {
    ctx: *const anyopaque,
    hasFilter: *const fn (ctx: *const anyopaque, name: []const u8) bool,
    hasTest: *const fn (ctx: *const anyopaque, name: []const u8) bool,
};

/// Tags the reference implementation has that this module deliberately does
/// not. They get a named error rather than "unknown tag", so the message says
/// what is going on instead of looking like a typo.
const unimplemented_tags = [_][]const u8{
    "extends", "block",    "endblock",  "include",    "import",
    "from",    "macro",    "endmacro",  "call",       "endcall",
    "trans",   "endtrans", "pluralize", "autoescape", "endautoescape",
};

pub fn parse(
    arena: std.mem.Allocator,
    pieces: []const lex.Piece,
    registry: Registry,
    diag: *Diagnostic,
) Error![]const Node {
    var p: Parser = .{ .arena = arena, .pieces = pieces, .registry = registry, .diag = diag };
    const body = try p.parseBody(&.{});
    if (p.idx < pieces.len) return p.failAt(pieces[p.idx].line, "unexpected end tag");
    return body.nodes;
}

const Body = struct {
    nodes: []const Node,
    /// The `{% end… %}`/`{% else %}`/`{% elif %}` keyword that closed it.
    ended_with: []const u8,
    end_toks: []const Token,
    end_line: usize,
};

const Parser = struct {
    arena: std.mem.Allocator,
    pieces: []const lex.Piece,
    idx: usize = 0,
    registry: Registry,
    diag: *Diagnostic,

    fn failAt(self: *Parser, line: usize, comptime msg: []const u8) Error {
        self.diag.set(line, "{s}", .{msg});
        return error.TemplateSyntaxError;
    }

    fn dupe(self: *Parser, e: Expr) Error!*const Expr {
        const p = try self.arena.create(Expr);
        p.* = e;
        return p;
    }

    fn parseBody(self: *Parser, stop: []const []const u8) Error!Body {
        var nodes: std.ArrayList(Node) = .empty;
        while (self.idx < self.pieces.len) {
            const piece = self.pieces[self.idx];
            switch (piece.chunk) {
                .text => |t| {
                    self.idx += 1;
                    if (t.len != 0) try nodes.append(self.arena, .{ .text = t });
                },
                .output => |toks| {
                    self.idx += 1;
                    var ts: Stream = .{ .toks = toks, .p = self };
                    const e = try ts.parseTupleTop(piece.line);
                    try ts.expectEnd(piece.line);
                    try nodes.append(self.arena, .{ .output = .{ .expr = e, .line = piece.line } });
                },
                .stmt => |toks| {
                    if (toks.len == 0) return self.failAt(piece.line, "empty statement tag");
                    const kw = toks[0];
                    if (kw.kind != .name) return self.failAt(piece.line, "statement must start with a tag name");
                    for (stop) |s| if (std.mem.eql(u8, s, kw.text)) {
                        self.idx += 1;
                        return .{
                            .nodes = nodes.items,
                            .ended_with = kw.text,
                            .end_toks = toks[1..],
                            .end_line = piece.line,
                        };
                    };
                    self.idx += 1;
                    try self.parseStatement(kw, toks, piece.line, &nodes);
                },
            }
        }
        if (stop.len != 0) {
            const line = if (self.pieces.len > 0) self.pieces[self.pieces.len - 1].line else 1;
            return self.failAt(line, "unclosed block at end of template");
        }
        return .{ .nodes = nodes.items, .ended_with = "", .end_toks = &.{}, .end_line = 0 };
    }

    fn parseStatement(
        self: *Parser,
        kw: Token,
        toks: []const Token,
        line: usize,
        out: *std.ArrayList(Node),
    ) Error!void {
        const rest = toks[1..];
        if (std.mem.eql(u8, kw.text, "if")) return self.parseIf(rest, line, out);
        if (std.mem.eql(u8, kw.text, "for")) return self.parseFor(rest, line, out);
        if (std.mem.eql(u8, kw.text, "set")) return self.parseSet(rest, line, out);
        if (std.mem.eql(u8, kw.text, "filter")) return self.parseFilterBlock(rest, line, out);
        if (std.mem.eql(u8, kw.text, "with")) return self.parseWith(rest, line, out);
        if (std.mem.eql(u8, kw.text, "do")) {
            var ts: Stream = .{ .toks = rest, .p = self };
            const e = try ts.parseExpression(line, true);
            try ts.expectEnd(line);
            try out.append(self.arena, .{ .do = .{ .expr = e, .line = line } });
            return;
        }
        for (unimplemented_tags) |t| if (std.mem.eql(u8, t, kw.text)) {
            return self.failAt(line, "tag is recognised but not implemented by this module (see SPEC.md's divergence table)");
        };
        return self.failAt(line, "unknown tag");
    }

    fn parseIf(self: *Parser, rest: []const Token, line: usize, out: *std.ArrayList(Node)) Error!void {
        var ts: Stream = .{ .toks = rest, .p = self };
        const cond = try ts.parseExpression(line, true);
        try ts.expectEnd(line);
        const node = try self.parseIfTail(cond);
        try out.append(self.arena, node);
    }

    /// `{% elif %}` is the same node type as `{% if %}`, nested in `orelse_`.
    fn parseIfTail(self: *Parser, cond: *const Expr) Error!Node {
        const body = try self.parseBody(&.{ "elif", "else", "endif" });
        if (std.mem.eql(u8, body.ended_with, "endif")) {
            return .{ .if_ = .{ .cond = cond, .body = body.nodes, .orelse_ = &.{} } };
        }
        if (std.mem.eql(u8, body.ended_with, "else")) {
            const else_body = try self.parseBody(&.{"endif"});
            return .{ .if_ = .{ .cond = cond, .body = body.nodes, .orelse_ = else_body.nodes } };
        }
        // elif
        var ts: Stream = .{ .toks = body.end_toks, .p = self };
        const sub_cond = try ts.parseExpression(body.end_line, true);
        try ts.expectEnd(body.end_line);
        const nested = try self.parseIfTail(sub_cond);
        const chain = try self.arena.alloc(Node, 1);
        chain[0] = nested;
        return .{ .if_ = .{ .cond = cond, .body = body.nodes, .orelse_ = chain } };
    }

    fn parseFor(self: *Parser, rest: []const Token, line: usize, out: *std.ArrayList(Node)) Error!void {
        var ts: Stream = .{ .toks = rest, .p = self };
        const target = try ts.parseTarget(line, false);
        if (!ts.eatName("in")) return self.failAt(line, "expected `in` in for-tag");
        const iterable = try ts.parseExpression(line, false);
        var cond: ?*const Expr = null;
        if (ts.eatName("if")) cond = try ts.parseExpression(line, false);
        if (ts.eatName("recursive")) return self.failAt(line, "`recursive` loops are not implemented (see SPEC.md)");
        try ts.expectEnd(line);

        const body = try self.parseBody(&.{ "else", "endfor" });
        var empty: []const Node = &.{};
        if (std.mem.eql(u8, body.ended_with, "else")) {
            const eb = try self.parseBody(&.{"endfor"});
            empty = eb.nodes;
        }
        try out.append(self.arena, .{ .for_ = .{
            .target = target,
            .iterable = iterable,
            .cond = cond,
            .body = body.nodes,
            .empty = empty,
            .recursive = false,
        } });
    }

    fn parseSet(self: *Parser, rest: []const Token, line: usize, out: *std.ArrayList(Node)) Error!void {
        var ts: Stream = .{ .toks = rest, .p = self };
        const target = try ts.parseTarget(line, true);
        if (ts.peek()) |t| {
            if (t.kind == .assign) {
                _ = ts.next();
                const e = try ts.parseTupleTop(line);
                try ts.expectEnd(line);
                try out.append(self.arena, .{ .set = .{ .target = target, .expr = e } });
                return;
            }
        }
        // Block form: `{% set x %}…{% endset %}`, optionally filtered.
        var filter: ?*const Expr = null;
        if (ts.peek() != null and ts.peek().?.kind == .pipe) {
            filter = try ts.parseFilterChain(&ast.filter_block_input, line);
        }
        try ts.expectEnd(line);
        const body = try self.parseBody(&.{"endset"});
        try out.append(self.arena, .{ .set_block = .{
            .target = target,
            .body = body.nodes,
            .filter = filter,
        } });
    }

    fn parseFilterBlock(self: *Parser, rest: []const Token, line: usize, out: *std.ArrayList(Node)) Error!void {
        var ts: Stream = .{ .toks = rest, .p = self };
        const chain = try ts.parseFilterChainBare(&ast.filter_block_input, line);
        try ts.expectEnd(line);
        const body = try self.parseBody(&.{"endfilter"});
        try out.append(self.arena, .{ .filter_block = .{ .filter = chain, .body = body.nodes } });
    }

    fn parseWith(self: *Parser, rest: []const Token, line: usize, out: *std.ArrayList(Node)) Error!void {
        var ts: Stream = .{ .toks = rest, .p = self };
        var assigns: std.ArrayList(ast.Set) = .empty;
        while (ts.peek() != null) {
            const target = try ts.parseTarget(line, true);
            if (ts.peek() == null or ts.peek().?.kind != .assign)
                return self.failAt(line, "expected `=` in with-tag");
            _ = ts.next();
            const e = try ts.parseExpression(line, true);
            try assigns.append(self.arena, .{ .target = target, .expr = e });
            if (ts.peek() != null and ts.peek().?.kind == .comma) {
                _ = ts.next();
                continue;
            }
            break;
        }
        try ts.expectEnd(line);
        const body = try self.parseBody(&.{"endwith"});
        try out.append(self.arena, .{ .with = .{ .assignments = assigns.items, .body = body.nodes } });
    }
};

/// A cursor over one tag's tokens plus the whole expression grammar.
const Stream = struct {
    toks: []const Token,
    i: usize = 0,
    p: *Parser,

    fn peek(self: *Stream) ?Token {
        return if (self.i < self.toks.len) self.toks[self.i] else null;
    }

    fn peekAt(self: *Stream, n: usize) ?Token {
        return if (self.i + n < self.toks.len) self.toks[self.i + n] else null;
    }

    fn next(self: *Stream) ?Token {
        if (self.i >= self.toks.len) return null;
        defer self.i += 1;
        return self.toks[self.i];
    }

    fn eat(self: *Stream, k: lex.Kind) bool {
        if (self.peek()) |t| if (t.kind == k) {
            self.i += 1;
            return true;
        };
        return false;
    }

    fn eatName(self: *Stream, n: []const u8) bool {
        if (self.peek()) |t| if (t.isName(n)) {
            self.i += 1;
            return true;
        };
        return false;
    }

    fn expect(self: *Stream, k: lex.Kind, line: usize, comptime msg: []const u8) Error!Token {
        if (self.peek()) |t| if (t.kind == k) {
            self.i += 1;
            return t;
        };
        return self.p.failAt(line, msg);
    }

    fn expectEnd(self: *Stream, line: usize) Error!void {
        if (self.i != self.toks.len) return self.p.failAt(line, "trailing tokens in tag");
    }

    fn dupe(self: *Stream, e: Expr) Error!*const Expr {
        return self.p.dupe(e);
    }

    // ── targets ─────────────────────────────────────────────────────────────

    fn parseTarget(self: *Stream, line: usize, allow_attr: bool) Error!ast.Target {
        const paren = self.eat(.lparen);
        var names: std.ArrayList([]const u8) = .empty;
        while (true) {
            const t = self.peek() orelse return self.p.failAt(line, "expected an assignment target");
            if (t.kind != .name) return self.p.failAt(line, "assignment target must be a name");
            _ = self.next();
            if (allow_attr and names.items.len == 0 and self.peek() != null and self.peek().?.kind == .dot) {
                _ = self.next();
                const attr = try self.expect(.name, line, "expected an attribute name after `.`");
                if (paren) _ = self.eat(.rparen);
                return .{ .attr = .{ .object = t.text, .name = attr.text } };
            }
            try names.append(self.p.arena, t.text);
            if (self.eat(.comma)) continue;
            break;
        }
        if (paren) _ = try self.expect(.rparen, line, "expected `)` closing the target list");
        if (names.items.len == 1) return .{ .name = names.items[0] };
        return .{ .tuple = names.items };
    }

    // ── expressions ─────────────────────────────────────────────────────────

    /// Top level of `{{ … }}` and of `{% set x = … %}`: a bare comma list is a
    /// tuple here, unlike inside a subexpression.
    fn parseTupleTop(self: *Stream, line: usize) Error!*const Expr {
        const first = try self.parseExpression(line, true);
        if (self.peek() == null or self.peek().?.kind != .comma) return first;
        var items: std.ArrayList(*const Expr) = .empty;
        try items.append(self.p.arena, first);
        while (self.eat(.comma)) {
            if (self.peek() == null) break;
            try items.append(self.p.arena, try self.parseExpression(line, true));
        }
        return self.dupe(.{ .tuple = items.items });
    }

    fn parseExpression(self: *Stream, line: usize, with_condexpr: bool) Error!*const Expr {
        if (with_condexpr) return self.parseCondExpr(line);
        return self.parseOr(line);
    }

    fn parseCondExpr(self: *Stream, line: usize) Error!*const Expr {
        var e = try self.parseOr(line);
        while (self.eatName("if")) {
            const cond = try self.parseOr(line);
            var otherwise: ?*const Expr = null;
            if (self.eatName("else")) otherwise = try self.parseCondExpr(line);
            e = try self.dupe(.{ .cond = .{ .then = e, .cond = cond, .otherwise = otherwise } });
        }
        return e;
    }

    fn parseOr(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parseAnd(line);
        while (self.eatName("or")) {
            const rhs = try self.parseAnd(line);
            lhs = try self.dupe(.{ .logical = .{ .op = .@"or", .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parseAnd(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parseNot(line);
        while (self.eatName("and")) {
            const rhs = try self.parseNot(line);
            lhs = try self.dupe(.{ .logical = .{ .op = .@"and", .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parseNot(self: *Stream, line: usize) Error!*const Expr {
        if (self.eatName("not")) {
            const inner = try self.parseNot(line);
            return self.dupe(.{ .not = inner });
        }
        return self.parseCompare(line);
    }

    fn parseCompare(self: *Stream, line: usize) Error!*const Expr {
        const first = try self.parseMath1(line);
        var links: std.ArrayList(ast.CompareLink) = .empty;
        while (true) {
            const t = self.peek() orelse break;
            var op: value.CmpOp = undefined;
            if (t.kind == .eq) {
                op = .eq;
            } else if (t.kind == .ne) {
                op = .ne;
            } else if (t.kind == .lt) {
                op = .lt;
            } else if (t.kind == .le) {
                op = .le;
            } else if (t.kind == .gt) {
                op = .gt;
            } else if (t.kind == .ge) {
                op = .ge;
            } else if (t.isName("in")) {
                op = .in;
            } else if (t.isName("not") and self.peekAt(1) != null and self.peekAt(1).?.isName("in")) {
                op = .not_in;
                self.i += 1;
            } else break;
            self.i += 1;
            const right = try self.parseMath1(line);
            try links.append(self.p.arena, .{ .op = op, .right = right });
        }
        if (links.items.len == 0) return first;
        return self.dupe(.{ .compare = .{ .first = first, .links = links.items } });
    }

    fn parseMath1(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parseConcat(line);
        while (self.peek()) |t| {
            const op: value.BinOp = switch (t.kind) {
                .add => .add,
                .sub => .sub,
                else => break,
            };
            self.i += 1;
            const rhs = try self.parseConcat(line);
            lhs = try self.dupe(.{ .binop = .{ .op = op, .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parseConcat(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parseMath2(line);
        while (self.eat(.tilde)) {
            const rhs = try self.parseMath2(line);
            lhs = try self.dupe(.{ .binop = .{ .op = .concat, .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parseMath2(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parsePow(line);
        while (self.peek()) |t| {
            const op: value.BinOp = switch (t.kind) {
                .mul => .mul,
                .div => .div,
                .floordiv => .floordiv,
                .mod => .mod,
                else => break,
            };
            self.i += 1;
            const rhs = try self.parsePow(line);
            lhs = try self.dupe(.{ .binop = .{ .op = op, .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parsePow(self: *Stream, line: usize) Error!*const Expr {
        var lhs = try self.parseUnary(line, true);
        while (self.eat(.pow)) {
            const rhs = try self.parseUnary(line, true);
            lhs = try self.dupe(.{ .binop = .{ .op = .pow, .lhs = lhs, .rhs = rhs } });
        }
        return lhs;
    }

    fn parseUnary(self: *Stream, line: usize, with_filter: bool) Error!*const Expr {
        var node: *const Expr = undefined;
        if (self.eat(.sub)) {
            node = try self.dupe(.{ .neg = try self.parseUnary(line, false) });
        } else if (self.eat(.add)) {
            node = try self.dupe(.{ .pos = try self.parseUnary(line, false) });
        } else {
            node = try self.parsePrimary(line);
        }
        node = try self.parsePostfix(node, line);
        if (with_filter) node = try self.parseFilterExpr(node, line);
        return node;
    }

    fn parsePrimary(self: *Stream, line: usize) Error!*const Expr {
        const t = self.peek() orelse return self.p.failAt(line, "unexpected end of expression");
        switch (t.kind) {
            .name => {
                self.i += 1;
                if (std.mem.eql(u8, t.text, "true") or std.mem.eql(u8, t.text, "True"))
                    return self.dupe(.{ .literal = .{ .boolean = true } });
                if (std.mem.eql(u8, t.text, "false") or std.mem.eql(u8, t.text, "False"))
                    return self.dupe(.{ .literal = .{ .boolean = false } });
                if (std.mem.eql(u8, t.text, "none") or std.mem.eql(u8, t.text, "None"))
                    return self.dupe(.{ .literal = .none });
                return self.dupe(.{ .name = t.text });
            },
            .string => {
                // Adjacent string literals concatenate, as in Python.
                var buf: std.ArrayList(u8) = .empty;
                try buf.appendSlice(self.p.arena, t.text);
                self.i += 1;
                while (self.peek()) |n| {
                    if (n.kind != .string) break;
                    try buf.appendSlice(self.p.arena, n.text);
                    self.i += 1;
                }
                return self.dupe(.{ .literal = Value.str(buf.items) });
            },
            .integer => {
                self.i += 1;
                return self.dupe(.{ .literal = .{ .integer = t.int } });
            },
            .float => {
                self.i += 1;
                return self.dupe(.{ .literal = .{ .float = t.float } });
            },
            .lparen => {
                self.i += 1;
                if (self.eat(.rparen)) return self.dupe(.{ .tuple = &.{} });
                const inner = try self.parseParenTuple(line);
                _ = try self.expect(.rparen, line, "expected `)`");
                return inner;
            },
            .lbracket => {
                self.i += 1;
                var items: std.ArrayList(*const Expr) = .empty;
                while (!self.eat(.rbracket)) {
                    if (items.items.len != 0) _ = try self.expect(.comma, line, "expected `,` in list literal");
                    if (self.eat(.rbracket)) break;
                    try items.append(self.p.arena, try self.parseExpression(line, true));
                }
                return self.dupe(.{ .list = items.items });
            },
            .lbrace => {
                self.i += 1;
                var entries: std.ArrayList(ast.DictEntry) = .empty;
                while (!self.eat(.rbrace)) {
                    if (entries.items.len != 0) _ = try self.expect(.comma, line, "expected `,` in dict literal");
                    if (self.eat(.rbrace)) break;
                    const k = try self.parseExpression(line, true);
                    _ = try self.expect(.colon, line, "expected `:` in dict literal");
                    const v = try self.parseExpression(line, true);
                    try entries.append(self.p.arena, .{ .key = k, .value = v });
                }
                return self.dupe(.{ .dict = entries.items });
            },
            else => return self.p.failAt(line, "unexpected token in expression"),
        }
    }

    /// Inside `(` `)`: a comma makes a tuple, a lone expression stays itself.
    fn parseParenTuple(self: *Stream, line: usize) Error!*const Expr {
        const first = try self.parseExpression(line, true);
        if (self.peek() == null or self.peek().?.kind != .comma) return first;
        var items: std.ArrayList(*const Expr) = .empty;
        try items.append(self.p.arena, first);
        while (self.eat(.comma)) {
            if (self.peek() != null and self.peek().?.kind == .rparen) break;
            try items.append(self.p.arena, try self.parseExpression(line, true));
        }
        return self.dupe(.{ .tuple = items.items });
    }

    fn parsePostfix(self: *Stream, start: *const Expr, line: usize) Error!*const Expr {
        var node = start;
        while (self.peek()) |t| {
            switch (t.kind) {
                .dot => {
                    self.i += 1;
                    const n = self.next() orelse return self.p.failAt(line, "expected a name after `.`");
                    const attr: []const u8 = switch (n.kind) {
                        .name => n.text,
                        // `a.0` is legal and means `a[0]`.
                        .integer => blk: {
                            const idx = try self.dupe(.{ .literal = .{ .integer = n.int } });
                            node = try self.dupe(.{ .getitem = .{ .obj = node, .index = idx } });
                            break :blk "";
                        },
                        else => return self.p.failAt(line, "expected a name after `.`"),
                    };
                    if (attr.len == 0) continue;
                    if (self.peek() != null and self.peek().?.kind == .lparen) {
                        const args = try self.parseCallArgs(line);
                        node = try self.dupe(.{ .method = .{ .obj = node, .name = attr, .args = args, .line = line } });
                    } else {
                        node = try self.dupe(.{ .getattr = .{ .obj = node, .name = attr } });
                    }
                },
                .lbracket => {
                    self.i += 1;
                    node = try self.parseSubscript(node, line);
                },
                .lparen => {
                    const args = try self.parseCallArgs(line);
                    node = try self.dupe(.{ .call = .{ .callee = node, .args = args, .line = line } });
                },
                else => break,
            }
        }
        return node;
    }

    fn parseSubscript(self: *Stream, obj: *const Expr, line: usize) Error!*const Expr {
        var start: ?*const Expr = null;
        if (self.peek() != null and self.peek().?.kind != .colon)
            start = try self.parseExpression(line, true);
        if (self.eat(.rbracket)) {
            if (start) |s| return self.dupe(.{ .getitem = .{ .obj = obj, .index = s } });
            return self.p.failAt(line, "empty subscript");
        }
        _ = try self.expect(.colon, line, "expected `:` or `]` in subscript");
        var stop: ?*const Expr = null;
        var step: ?*const Expr = null;
        if (self.peek() != null and self.peek().?.kind != .colon and self.peek().?.kind != .rbracket)
            stop = try self.parseExpression(line, true);
        if (self.eat(.colon)) {
            if (self.peek() != null and self.peek().?.kind != .rbracket)
                step = try self.parseExpression(line, true);
        }
        _ = try self.expect(.rbracket, line, "expected `]` closing the slice");
        return self.dupe(.{ .slice = .{ .obj = obj, .start = start, .stop = stop, .step = step } });
    }

    fn parseCallArgs(self: *Stream, line: usize) Error!ast.Args {
        _ = try self.expect(.lparen, line, "expected `(`");
        var positional: std.ArrayList(*const Expr) = .empty;
        var keyword: std.ArrayList(ast.Kwarg) = .empty;
        while (!self.eat(.rparen)) {
            if (positional.items.len + keyword.items.len != 0)
                _ = try self.expect(.comma, line, "expected `,` between arguments");
            if (self.eat(.rparen)) break;
            if (self.peek() != null and (self.peek().?.kind == .mul or self.peek().?.kind == .pow))
                return self.p.failAt(line, "`*args`/`**kwargs` are not implemented (see SPEC.md)");
            const t = self.peek() orelse return self.p.failAt(line, "unterminated argument list");
            if (t.kind == .name and self.peekAt(1) != null and self.peekAt(1).?.kind == .assign) {
                self.i += 2;
                const v = try self.parseExpression(line, true);
                try keyword.append(self.p.arena, .{ .name = t.text, .value = v });
            } else {
                if (keyword.items.len != 0)
                    return self.p.failAt(line, "positional argument after a keyword argument");
                try positional.append(self.p.arena, try self.parseExpression(line, true));
            }
        }
        return .{ .positional = positional.items, .keyword = keyword.items };
    }

    /// `| filter` and `is test`, the tightest-binding postfix layer.
    fn parseFilterExpr(self: *Stream, start: *const Expr, line: usize) Error!*const Expr {
        var node = start;
        while (self.peek()) |t| {
            if (t.kind == .pipe) {
                node = try self.parseOneFilter(node, line);
            } else if (t.isName("is")) {
                self.i += 1;
                node = try self.parseTest(node, line);
            } else if (t.kind == .lparen) {
                const args = try self.parseCallArgs(line);
                node = try self.dupe(.{ .call = .{ .callee = node, .args = args, .line = line } });
            } else break;
        }
        return node;
    }

    fn parseFilterChain(self: *Stream, start: *const Expr, line: usize) Error!*const Expr {
        var node = start;
        while (self.peek() != null and self.peek().?.kind == .pipe) node = try self.parseOneFilter(node, line);
        return node;
    }

    /// `{% filter name(…) | other %}` — the leading `|` is implicit.
    fn parseFilterChainBare(self: *Stream, start: *const Expr, line: usize) Error!*const Expr {
        const name = try self.expect(.name, line, "expected a filter name");
        var node = try self.finishFilter(start, name, line);
        while (self.peek() != null and self.peek().?.kind == .pipe) node = try self.parseOneFilter(node, line);
        return node;
    }

    fn parseOneFilter(self: *Stream, input: *const Expr, line: usize) Error!*const Expr {
        _ = try self.expect(.pipe, line, "expected `|`");
        const name = try self.expect(.name, line, "expected a filter name after `|`");
        return self.finishFilter(input, name, line);
    }

    fn finishFilter(self: *Stream, input: *const Expr, name: Token, line: usize) Error!*const Expr {
        if (!self.p.registry.hasFilter(self.p.registry.ctx, name.text))
            return self.p.failAt(line, "unknown filter — every filter name is resolved at compile time (see README's filter table)");
        var args: ast.Args = .{};
        if (self.peek() != null and self.peek().?.kind == .lparen) args = try self.parseCallArgs(line);
        return self.dupe(.{ .filter = .{ .input = input, .name = name.text, .args = args, .line = line } });
    }

    fn parseTest(self: *Stream, input: *const Expr, line: usize) Error!*const Expr {
        const negated = self.eatName("not");
        const name_tok = self.next() orelse return self.p.failAt(line, "expected a test name after `is`");
        if (name_tok.kind != .name) return self.p.failAt(line, "expected a test name after `is`");
        var name = name_tok.text;
        // `is not none` reads as the `none` test, negated; `x is none` as itself.
        if (!self.p.registry.hasTest(self.p.registry.ctx, name)) {
            if (std.mem.eql(u8, name, "None")) {
                name = "none";
            } else {
                return self.p.failAt(line, "unknown test — every test name is resolved at compile time (see README's test table)");
            }
        }
        var args: ast.Args = .{};
        if (self.peek() != null and self.peek().?.kind == .lparen) {
            args = try self.parseCallArgs(line);
        } else if (self.peek()) |t| {
            const takes_arg = switch (t.kind) {
                .name => !(t.isName("else") or t.isName("or") or t.isName("and") or t.isName("if") or t.isName("is")),
                .string, .integer, .float, .lbracket, .lbrace => true,
                else => false,
            };
            if (takes_arg) {
                const arg = try self.parsePrimary(line);
                const full = try self.parsePostfix(arg, line);
                const one = try self.p.arena.alloc(*const Expr, 1);
                one[0] = full;
                args = .{ .positional = one };
            }
        }
        return self.dupe(.{ .do_test = .{
            .input = input,
            .name = name,
            .args = args,
            .negated = negated,
            .line = line,
        } });
    }
};
