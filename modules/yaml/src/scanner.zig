// SPDX-License-Identifier: MIT
//! YAML 1.2 scanner — UTF-8 source bytes → a token stream.
//!
//! This is stage 1 of the three-stage pipeline described in `root.zig`. It is
//! the stage that owns every hard part of YAML's syntax: block indentation
//! (`BlockSequenceStart`/`BlockMappingStart`/`BlockEnd` are *synthesized* here,
//! they have no textual representation), the "simple key" lookahead that lets
//! `a: b` be recognised only once the `:` is seen, and the five scalar styles
//! with their folding and chomping rules.
//!
//! Two mechanisms deserve a note because nothing else in this repo looks like
//! them:
//!
//! * **Retroactive `Key` insertion.** When the scanner emits a plain/quoted
//!   scalar it does not yet know whether the scalar is a mapping key. It
//!   records a `SimpleKey` (position in the *token queue*, not the source),
//!   and when a `:` shows up on the same line it splices a `Key` token — and,
//!   in block context, a `BlockMappingStart` — into the queue *before* the
//!   already-emitted scalar. That is why the queue is an ArrayList with a head
//!   index rather than a plain FIFO.
//!
//! * **`indent` / `indents`.** `indent` is the column of the innermost open
//!   block collection (-1 = none). Any token starting left of it unrolls the
//!   stack, emitting one `BlockEnd` per level. This is the entirety of YAML's
//!   block-structure closing logic; the parser never sees a column.
//!
//! Every string a token carries is arena-allocated by the caller-supplied
//! allocator and lives as long as that arena.

const std = @import("std");

pub const ScalarStyle = enum { plain, single_quoted, double_quoted, literal, folded };

pub const Mark = struct {
    index: usize = 0,
    line: usize = 0,
    column: usize = 0,
};

pub const TokenKind = enum {
    stream_start,
    stream_end,
    version_directive,
    tag_directive,
    document_start,
    document_end,
    block_sequence_start,
    block_mapping_start,
    block_end,
    flow_sequence_start,
    flow_sequence_end,
    flow_mapping_start,
    flow_mapping_end,
    block_entry,
    flow_entry,
    key,
    value,
    alias,
    anchor,
    tag,
    scalar,
};

pub const Token = struct {
    kind: TokenKind,
    start: Mark = .{},
    end: Mark = .{},
    /// scalar text, anchor name or alias name
    value: []const u8 = "",
    /// `.tag`: the handle (`!`, `!!`, `!e!`, or "" for a verbatim `!<…>` tag).
    /// `.tag_directive`: the handle being defined.
    handle: []const u8 = "",
    /// `.tag`: the suffix. `.tag_directive`: the prefix it expands to.
    suffix: []const u8 = "",
    style: ScalarStyle = .plain,
    major: u32 = 0,
    minor: u32 = 0,
};

pub const Error = error{
    OutOfMemory,
    /// The input is not a well-formed YAML stream. `Scanner.problem` carries a
    /// human-readable description and `Scanner.problem_mark` its position.
    InvalidYaml,
};

const SimpleKey = struct {
    possible: bool = false,
    required: bool = false,
    /// index into the *logical* token stream (`tokens_parsed` + queue offset)
    token_number: usize = 0,
    mark: Mark = .{},
};

/// Bound on `indents` + `flow_level` so a hostile input cannot make the
/// scanner allocate without limit. Far above anything a real document needs;
/// the deepest case in the yaml-test-suite nests 8 levels.
pub const max_depth: usize = 4096;

pub const Scanner = struct {
    arena: std.mem.Allocator,
    src: []const u8,

    pos: usize = 0,
    line: usize = 0,
    column: usize = 0,

    tokens: std.ArrayList(Token) = .empty,
    head: usize = 0,
    tokens_parsed: usize = 0,
    token_available: bool = false,

    stream_start_produced: bool = false,
    stream_end_produced: bool = false,

    indent: i64 = -1,
    indents: std.ArrayList(i64) = .empty,

    simple_key_allowed: bool = true,
    flow_level: usize = 0,
    simple_keys: std.ArrayList(SimpleKey) = .empty,
    /// Per open flow collection, innermost last: true for `[`, false for `{`.
    /// `simple_keys[i]` (i >= 1) lives inside `flow_is_seq[i - 1]`. Needed
    /// because the two collections give an implicit key *different* spans —
    /// see `staleSimpleKeys`.
    flow_is_seq: std.ArrayList(bool) = .empty,

    /// The previous token was a *JSON-like* flow node (a quoted scalar or a
    /// `]`/`}`), so a following `:` is a value indicator even with no space
    /// after it — YAML 1.2's JSON-compatible flow syntax, `{"a":1}`. The suite
    /// (`K3WX`, `5MUD`) shows this survives an intervening comment and line
    /// break, so it is a flag on the token, not an adjacency of source bytes.
    flow_json_key: bool = false,

    /// True while nothing but blanks has been seen since the line started.
    only_blanks: bool = true,
    /// A tab has been consumed as separation somewhere on the current line.
    /// A tab can never be indentation (YAML 1.2 §6.1), so no block collection
    /// may *open* at a column reached past one — that is the whole content of
    /// the suite's `Y79Y` tab family.
    tab_on_line: bool = false,
    /// Leading *spaces* of the current line. Flow continuation lines are
    /// measured against this, not against `column`, so a tab cannot smuggle a
    /// flow collection past its parent's indentation either.
    line_spaces: i64 = 0,

    problem: []const u8 = "",
    problem_mark: Mark = .{},

    const Self = @This();

    pub fn init(arena: std.mem.Allocator, src: []const u8) Self {
        return .{ .arena = arena, .src = src };
    }

    fn fail(self: *Self, msg: []const u8) Error {
        if (self.problem.len == 0) {
            self.problem = msg;
            self.problem_mark = self.mark();
        }
        return error.InvalidYaml;
    }

    fn failAt(self: *Self, msg: []const u8, m: Mark) Error {
        if (self.problem.len == 0) {
            self.problem = msg;
            self.problem_mark = m;
        }
        return error.InvalidYaml;
    }

    // ── character-level helpers ─────────────────────────────────────────────

    fn at(self: *const Self, n: usize) u8 {
        const i = self.pos + n;
        return if (i < self.src.len) self.src[i] else 0;
    }

    fn eof(self: *const Self) bool {
        return self.pos >= self.src.len;
    }

    fn mark(self: *const Self) Mark {
        return .{ .index = self.pos, .line = self.line, .column = self.column };
    }

    fn charWidth(b: u8) usize {
        if (b < 0x80) return 1;
        if (b < 0xC0) return 1; // stray continuation byte — consume one
        if (b < 0xE0) return 2;
        if (b < 0xF0) return 3;
        return 4;
    }

    /// Advance one *character* (not byte); columns count characters.
    ///
    /// Line-start accounting (`only_blanks`, `line_spaces`, `tab_on_line`)
    /// lives here rather than at the call sites, because leading blanks are
    /// consumed from *three* places: `scanToNextToken`, and the continuation
    /// folding loops of `scanPlainScalar`/`scanFlowScalar`. When only the first
    /// maintained it, `line_spaces` under-reported the indentation of any line
    /// a folded scalar had already walked into, and the flow-indent check in
    /// `fetchNextToken` rejected valid documents (`ZF4X`, `VJP3/01`, `LP6E`).
    fn skip(self: *Self) void {
        if (self.eof()) return;
        const c = self.src[self.pos];
        self.countChar(c);
        const w = charWidth(c);
        self.pos = @min(self.pos + w, self.src.len);
        self.column += 1;
    }

    /// A tab is separation, never indentation (YAML 1.2 §6.1), so it is
    /// recorded but never counted towards `line_spaces`.
    fn countChar(self: *Self, c: u8) void {
        if (!isBlank(c)) {
            self.only_blanks = false;
        } else if (c == '\t') {
            self.tab_on_line = true;
        } else if (self.only_blanks) {
            self.line_spaces += 1;
        }
    }

    fn skipN(self: *Self, n: usize) void {
        for (0..n) |_| self.skip();
    }

    /// Advance across a line break (CRLF counts as one) and reset the column.
    fn skipLine(self: *Self) void {
        if (self.at(0) == '\r' and self.at(1) == '\n') {
            self.pos += 2;
        } else if (self.at(0) == '\r' or self.at(0) == '\n') {
            self.pos += 1;
        } else return;
        self.line += 1;
        self.column = 0;
        self.only_blanks = true;
        self.tab_on_line = false;
        self.line_spaces = 0;
    }

    fn read(self: *Self, out: *std.ArrayList(u8)) Error!void {
        if (self.eof()) return;
        self.countChar(self.src[self.pos]);
        const w = @min(charWidth(self.src[self.pos]), self.src.len - self.pos);
        try out.appendSlice(self.arena, self.src[self.pos .. self.pos + w]);
        self.pos += w;
        self.column += 1;
    }

    /// Consume a line break, appending the *normalized* form (always LF).
    ///
    /// Appends **only** when it actually consumes. `skipLine` is a no-op when
    /// the cursor is not on a break, so without this guard `readLine` is an
    /// append-without-consume primitive — exactly the shape that turns a
    /// mis-guarded caller into an unbounded allocation. Every caller does guard
    /// with `breakAt(0)` today; this makes that a property of the primitive
    /// rather than of each call site.
    fn readLine(self: *Self, out: *std.ArrayList(u8)) Error!void {
        if (!self.breakAt(0)) return;
        try out.append(self.arena, '\n');
        self.skipLine();
    }

    fn isBlank(c: u8) bool {
        return c == ' ' or c == '\t';
    }
    /// YAML 1.2 restricts line breaks to LF and CR (1.1's NEL/LS/PS are plain
    /// content here) — see SPEC.md.
    fn isBreak(c: u8) bool {
        return c == '\n' or c == '\r';
    }

    fn blankAt(self: *const Self, n: usize) bool {
        return isBlank(self.at(n));
    }
    fn breakAt(self: *const Self, n: usize) bool {
        return isBreak(self.at(n));
    }
    fn breakzAt(self: *const Self, n: usize) bool {
        return self.pos + n >= self.src.len or isBreak(self.at(n));
    }
    fn blankzAt(self: *const Self, n: usize) bool {
        return self.blankAt(n) or self.breakzAt(n);
    }

    /// True when only blanks separate the cursor from the end of the line —
    /// i.e. this line carries no content, so its blanks indent nothing.
    fn restOfLineBlank(self: *const Self) bool {
        var n: usize = 0;
        while (self.blankAt(n)) n += 1;
        return self.breakzAt(n);
    }

    fn isFlowIndicator(c: u8) bool {
        return c == ',' or c == '[' or c == ']' or c == '{' or c == '}';
    }

    // ── token queue ─────────────────────────────────────────────────────────

    fn queueLen(self: *const Self) usize {
        return self.tokens.items.len - self.head;
    }

    fn enqueue(self: *Self, tok: Token) Error!void {
        try self.tokens.append(self.arena, tok);
    }

    fn insertToken(self: *Self, offset: usize, tok: Token) Error!void {
        try self.tokens.insert(self.arena, self.head + offset, tok);
    }

    /// Peek the next token, scanning more input if the queue is empty.
    ///
    /// **Termination is structural.** `needMoreTokens` can hold with a
    /// non-empty queue (the head token may sit before an unresolved simple
    /// key), so this loop is not bounded by the queue being empty. What bounds
    /// it is the invariant asserted below: every `fetchMoreTokens` must either
    /// advance `pos` or grow the queue. `pos` is monotone and bounded by
    /// `src.len`, and past EOF `fetchNextToken` is a no-op (`stream_end` is
    /// produced at most once), so a scanner state that cannot make progress
    /// surfaces here as one bounded error instead of spinning.
    ///
    /// This is not hypothetical. Before the fixes below, `[` alone parked an
    /// unresolvable simple key at the queue head, `needMoreTokens` stayed true
    /// forever, and each iteration appended a *fresh* `stream_end` token —
    /// unbounded queue growth that reached 15.4 GB RSS and OOM-killed the host.
    pub fn peek(self: *Self) Error!*Token {
        while (true) {
            if (self.queueLen() > 0 and self.token_available) {
                return &self.tokens.items[self.head];
            }
            if (self.needMoreTokens()) {
                const pos_before = self.pos;
                const queued_before = self.tokens.items.len;
                try self.fetchMoreTokens();
                if (self.pos == pos_before and self.tokens.items.len == queued_before)
                    return self.fail("scanner made no progress");
            } else {
                self.token_available = true;
                return &self.tokens.items[self.head];
            }
        }
    }

    pub fn next(self: *Self) Error!Token {
        const t = try self.peek();
        const copy = t.*;
        // `stream_end` is **sticky**: it is never popped, so the queue can
        // never drain back to empty once the stream has ended, and no caller
        // can walk off the end by peeking past it. Together with the
        // `stream_end_produced` guard in `fetchNextToken` this makes the token
        // stream monotone and finite by construction.
        if (copy.kind == .stream_end) return copy;
        self.head += 1;
        self.tokens_parsed += 1;
        self.token_available = false;
        if (self.head == self.tokens.items.len) {
            self.head = 0;
            self.tokens.clearRetainingCapacity();
        }
        return copy;
    }

    fn needMoreTokens(self: *Self) bool {
        if (self.queueLen() == 0) return true;
        // A queued token may still be *before* a simple key that has not been
        // resolved yet; in that case it cannot be handed out.
        for (self.simple_keys.items) |sk| {
            if (sk.possible and sk.token_number == self.tokens_parsed) return true;
        }
        return false;
    }

    fn fetchMoreTokens(self: *Self) Error!void {
        try self.fetchNextToken();
    }

    // ── the main dispatch ───────────────────────────────────────────────────

    fn fetchNextToken(self: *Self) Error!void {
        if (!self.stream_start_produced) return self.fetchStreamStart();
        // At most one `stream_end`, ever. `peek`'s progress assertion turns any
        // caller that still asks for more into a bounded error.
        if (self.stream_end_produced) return;

        try self.scanToNextToken();
        try self.staleSimpleKeys();
        try self.unrollIndent(@intCast(self.column));

        if (self.eof()) return self.fetchStreamEnd();

        // Flow content on a continuation line must be indented past its
        // enclosing block node (YAML 1.2 §7.4) — and only *spaces* count, so a
        // tab-indented flow entry is rejected (`9C9N`, `Y79Y/003`).
        if (self.flow_level > 0 and self.only_blanks and self.line_spaces <= self.indent)
            return self.fail("flow content must be indented more than its parent block node");

        const json_key = self.flow_json_key;
        self.flow_json_key = false;
        const c = self.at(0);

        if (self.column == 0 and c == '%') return self.fetchDirective();
        if (self.column == 0 and c == '-' and self.at(1) == '-' and self.at(2) == '-' and self.blankzAt(3))
            return self.fetchDocumentIndicator(.document_start);
        if (self.column == 0 and c == '.' and self.at(1) == '.' and self.at(2) == '.' and self.blankzAt(3))
            return self.fetchDocumentIndicator(.document_end);

        switch (c) {
            '[' => return self.fetchFlowCollectionStart(.flow_sequence_start),
            '{' => return self.fetchFlowCollectionStart(.flow_mapping_start),
            ']' => return self.fetchFlowCollectionEnd(.flow_sequence_end),
            '}' => return self.fetchFlowCollectionEnd(.flow_mapping_end),
            ',' => return self.fetchFlowEntry(),
            '*' => return self.fetchAnchor(.alias),
            '&' => return self.fetchAnchor(.anchor),
            '!' => return self.fetchTag(),
            '\'' => return self.fetchFlowScalar(.single_quoted),
            '"' => return self.fetchFlowScalar(.double_quoted),
            else => {},
        }
        if (c == '-' and self.blankzAt(1)) return self.fetchBlockEntry();
        // `{?foo: bar}` is the plain scalar `?foo`, not an explicit key
        // (`652Z`, `HM87/01`): `?` only indicates a key when separation or a
        // flow indicator follows it.
        if (c == '?' and (self.blankzAt(1) or
            (self.flow_level > 0 and isFlowIndicator(self.at(1))))) return self.fetchKey();
        if (c == ':' and (self.blankzAt(1) or
            (self.flow_level > 0 and (json_key or isFlowIndicator(self.at(1))))))
            return self.fetchValue();
        if (c == '|' and self.flow_level == 0) return self.fetchBlockScalar(.literal);
        if (c == '>' and self.flow_level == 0) return self.fetchBlockScalar(.folded);

        if (self.plainAllowed()) return self.fetchPlainScalar();
        return self.fail("found character that cannot start any token");
    }

    /// The set of characters a plain scalar may begin with (YAML 1.2 §7.3.3,
    /// `ns-plain-first`): every indicator is excluded, except `-`/`?`/`:` when
    /// not followed by a space (block context only for `?`/`:`).
    fn plainAllowed(self: *const Self) bool {
        const c = self.at(0);
        const is_indicator = switch (c) {
            '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`' => true,
            else => false,
        };
        if (!is_indicator) return true;
        // `ns-plain-first` also admits `-`/`?`/`:` when what follows is
        // `ns-plain-safe(c)` — which in flow context excludes the flow
        // indicators. That exclusion is what makes `[-]` and `[-, -]` errors
        // while `[:x]` and `- ::vector` are scalars.
        if (c == '-' or c == '?' or c == ':') {
            if (self.blankzAt(1)) return false;
            if (self.flow_level > 0 and isFlowIndicator(self.at(1))) return false;
            return true;
        }
        return false;
    }

    // ── whitespace / comments ───────────────────────────────────────────────

    /// A `#` only opens a comment at the start of a line or after a blank —
    /// `[a]#x`, `"v"# x` and `>#c` are errors, not comments (`9JBA`, `CVW2`,
    /// `SU5Z`, `X4QW`, `MUS6/00`).
    fn commentHere(self: *const Self) bool {
        if (self.at(0) != '#') return false;
        if (self.pos == 0 or self.column == 0) return true;
        return isBlank(self.src[self.pos - 1]) or isBreak(self.src[self.pos - 1]);
    }

    fn scanToNextToken(self: *Self) Error!void {
        while (true) {
            // A BOM is permitted at the start of any line and is not content.
            if (self.column == 0 and self.at(0) == 0xEF and self.at(1) == 0xBB and self.at(2) == 0xBF)
                self.skip();

            // Tabs are legal *separation* anywhere, but never indentation.
            // Both facts are recorded by `skip` (see `countChar`) rather than
            // acted on here; `rollIndent` and the flow-indent check in
            // `fetchNextToken` are what enforce them.
            while (self.blankAt(0)) self.skip();

            if (self.commentHere()) {
                while (!self.breakzAt(0)) self.skip();
            }

            if (self.breakAt(0)) {
                self.skipLine();
                if (self.flow_level == 0) self.simple_key_allowed = true;
            } else break;
        }
    }

    // ── indentation ─────────────────────────────────────────────────────────

    fn rollIndent(self: *Self, column: i64, kind: TokenKind, m: Mark, offset: ?usize) Error!void {
        if (self.flow_level > 0) return;
        if (self.indent < column) {
            // Opening a block collection needs real indentation, and a tab is
            // not indentation — `-\t-` and `?\tkey:` are errors even though
            // `-\t-1` (a plain scalar, no new collection) is fine.
            if (self.tab_on_line)
                return self.fail("found a tab character where an indentation space is expected");
            if (self.indents.items.len >= max_depth) return self.fail("exceeded maximum block nesting depth");
            try self.indents.append(self.arena, self.indent);
            self.indent = column;
            const tok = Token{ .kind = kind, .start = m, .end = m };
            if (offset) |o| try self.insertToken(o, tok) else try self.enqueue(tok);
        }
    }

    fn unrollIndent(self: *Self, column: i64) Error!void {
        if (self.flow_level > 0) return;
        while (self.indent > column) {
            const m = self.mark();
            try self.enqueue(.{ .kind = .block_end, .start = m, .end = m });
            self.indent = self.indents.pop() orelse -1;
        }
    }

    // ── simple keys ─────────────────────────────────────────────────────────

    fn staleSimpleKeys(self: *Self) Error!void {
        for (self.simple_keys.items, 0..) |*sk, i| {
            if (!sk.possible) continue;
            // How far an implicit key may reach before its `:` differs by
            // context, and YAML 1.2 §7.4 makes the distinction precisely:
            //
            //   * block context — `ns-s-implicit-yaml-key(block-key)`, which
            //     ends in `s-separate-in-line?`: one line only.
            //   * a flow **mapping** — `ns-flow-map-yaml-key-entry` uses
            //     `s-separate`, which *does* admit a line break, so `{ multi\n
            //     line: value }` and `{ k\n : v }` are legal (`NJ66`, `9SA2`,
            //     `VJP3/01`).
            //   * a flow **sequence** — a single-pair entry uses
            //     `ns-s-implicit-yaml-key(flow-key)`, `s-separate-in-line?`
            //     again: no line break. `[ key\n : value ]` is an error
            //     (`DK4H`, `ZXT5`).
            //
            // All three are additionally capped at 1024 characters.
            const in_flow_seq = i > 0 and i <= self.flow_is_seq.items.len and
                self.flow_is_seq.items[i - 1];
            const line_broken = ((self.flow_level == 0 and i == 0) or in_flow_seq) and
                sk.mark.line < self.line;
            if (line_broken or sk.mark.index + 1024 < self.pos) {
                if (sk.required)
                    return self.failAt("could not find expected ':'", self.mark());
                sk.possible = false;
            }
        }
    }

    fn saveSimpleKey(self: *Self) Error!void {
        const required = self.flow_level == 0 and self.indent == @as(i64, @intCast(self.column));
        if (self.simple_key_allowed) {
            try self.removeSimpleKey();
            const sk = SimpleKey{
                .possible = true,
                .required = required,
                .token_number = self.tokens_parsed + self.queueLen(),
                .mark = self.mark(),
            };
            self.simple_keys.items[self.simple_keys.items.len - 1] = sk;
        }
    }

    fn removeSimpleKey(self: *Self) Error!void {
        const sk = &self.simple_keys.items[self.simple_keys.items.len - 1];
        if (sk.possible and sk.required)
            return self.failAt("could not find expected ':'", self.mark());
        sk.possible = false;
    }

    fn increaseFlowLevel(self: *Self, is_sequence: bool) Error!void {
        if (self.flow_level >= max_depth) return self.fail("exceeded maximum flow nesting depth");
        try self.simple_keys.append(self.arena, .{});
        try self.flow_is_seq.append(self.arena, is_sequence);
        self.flow_level += 1;
    }

    fn decreaseFlowLevel(self: *Self) void {
        if (self.flow_level > 0) {
            self.flow_level -= 1;
            _ = self.simple_keys.pop();
            _ = self.flow_is_seq.pop();
        }
    }

    // ── individual token fetchers ───────────────────────────────────────────

    fn fetchStreamStart(self: *Self) Error!void {
        try self.simple_keys.append(self.arena, .{});
        self.stream_start_produced = true;
        // A leading BOM belongs to the stream, not to the first token.
        if (self.at(0) == 0xEF and self.at(1) == 0xBB and self.at(2) == 0xBF) self.pos += 3;
        const m = self.mark();
        try self.enqueue(.{ .kind = .stream_start, .start = m, .end = m });
    }

    fn fetchStreamEnd(self: *Self) Error!void {
        if (self.column != 0) {
            self.column = 0;
            self.line += 1;
        }
        try self.unrollIndent(-1);
        // Every level, not just the innermost. `removeSimpleKey` clears only
        // the current flow level, so an unterminated flow collection (`[`) used
        // to leave the *outer* level's simple key `possible` forever — and a
        // possible simple key at the head of the queue makes `needMoreTokens`
        // permanently true. That was the runaway; see `peek`.
        for (self.simple_keys.items) |*sk| {
            if (!sk.possible) continue;
            if (sk.required) return self.failAt("could not find expected ':'", self.mark());
            sk.possible = false;
        }
        self.simple_key_allowed = false;
        const m = self.mark();
        self.stream_end_produced = true;
        try self.enqueue(.{ .kind = .stream_end, .start = m, .end = m });
    }

    fn fetchDirective(self: *Self) Error!void {
        try self.unrollIndent(-1);
        try self.removeSimpleKey();
        self.simple_key_allowed = false;
        const tok = try self.scanDirective();
        try self.enqueue(tok);
    }

    fn fetchDocumentIndicator(self: *Self, kind: TokenKind) Error!void {
        try self.unrollIndent(-1);
        try self.removeSimpleKey();
        self.simple_key_allowed = false;
        const start = self.mark();
        self.skipN(3);
        // YAML 1.2 §9.1.4: `l-document-suffix ::= c-document-end s-l-comments`
        // — only a comment may follow `...` on its line, so `... invalid` is an
        // error rather than a fresh bare document (`3HFZ`). `---` has no such
        // restriction: `--- scalar` is ordinary.
        if (kind == .document_end) {
            while (self.blankAt(0)) self.skip();
            if (!self.breakzAt(0) and !self.commentHere())
                return self.fail("found content after a document end marker");
        }
        try self.enqueue(.{ .kind = kind, .start = start, .end = self.mark() });
    }

    fn fetchFlowCollectionStart(self: *Self, kind: TokenKind) Error!void {
        try self.saveSimpleKey();
        try self.increaseFlowLevel(kind == .flow_sequence_start);
        self.simple_key_allowed = true;
        const start = self.mark();
        self.skip();
        try self.enqueue(.{ .kind = kind, .start = start, .end = self.mark() });
    }

    fn fetchFlowCollectionEnd(self: *Self, kind: TokenKind) Error!void {
        try self.removeSimpleKey();
        self.decreaseFlowLevel();
        self.simple_key_allowed = false;
        const start = self.mark();
        self.skip();
        // `[[1,2]: v]` — a flow collection is a JSON-like node, so a following
        // `:` is a value indicator with no separation needed.
        if (self.flow_level > 0) self.flow_json_key = true;
        try self.enqueue(.{ .kind = kind, .start = start, .end = self.mark() });
    }

    fn fetchFlowEntry(self: *Self) Error!void {
        try self.removeSimpleKey();
        self.simple_key_allowed = true;
        const start = self.mark();
        self.skip();
        try self.enqueue(.{ .kind = .flow_entry, .start = start, .end = self.mark() });
    }

    fn fetchBlockEntry(self: *Self) Error!void {
        if (self.flow_level == 0) {
            if (!self.simple_key_allowed)
                return self.fail("block sequence entries are not allowed in this context");
            try self.rollIndent(@intCast(self.column), .block_sequence_start, self.mark(), null);
        }
        try self.removeSimpleKey();
        self.simple_key_allowed = true;
        const start = self.mark();
        self.skip();
        try self.enqueue(.{ .kind = .block_entry, .start = start, .end = self.mark() });
    }

    fn fetchKey(self: *Self) Error!void {
        if (self.flow_level == 0) {
            if (!self.simple_key_allowed)
                return self.fail("mapping keys are not allowed in this context");
            try self.rollIndent(@intCast(self.column), .block_mapping_start, self.mark(), null);
        }
        try self.removeSimpleKey();
        self.simple_key_allowed = self.flow_level == 0;
        const start = self.mark();
        self.skip();
        try self.enqueue(.{ .kind = .key, .start = start, .end = self.mark() });
    }

    fn fetchValue(self: *Self) Error!void {
        const sk = &self.simple_keys.items[self.simple_keys.items.len - 1];
        if (sk.possible) {
            const offset = sk.token_number - self.tokens_parsed;
            try self.insertToken(offset, .{ .kind = .key, .start = sk.mark, .end = sk.mark });
            if (self.flow_level == 0)
                try self.rollIndent(@intCast(sk.mark.column), .block_mapping_start, sk.mark, offset);
            sk.possible = false;
            self.simple_key_allowed = false;
        } else {
            if (self.flow_level == 0) {
                if (!self.simple_key_allowed)
                    return self.fail("mapping values are not allowed in this context");
                try self.rollIndent(@intCast(self.column), .block_mapping_start, self.mark(), null);
            }
            self.simple_key_allowed = self.flow_level == 0;
        }
        const start = self.mark();
        self.skip();
        try self.enqueue(.{ .kind = .value, .start = start, .end = self.mark() });
    }

    fn fetchAnchor(self: *Self, kind: TokenKind) Error!void {
        try self.saveSimpleKey();
        self.simple_key_allowed = false;
        const tok = try self.scanAnchor(kind);
        try self.enqueue(tok);
    }

    fn fetchTag(self: *Self) Error!void {
        try self.saveSimpleKey();
        self.simple_key_allowed = false;
        const tok = try self.scanTag();
        try self.enqueue(tok);
    }

    fn fetchBlockScalar(self: *Self, style: ScalarStyle) Error!void {
        try self.removeSimpleKey();
        self.simple_key_allowed = true;
        const tok = try self.scanBlockScalar(style);
        try self.enqueue(tok);
    }

    fn fetchFlowScalar(self: *Self, style: ScalarStyle) Error!void {
        try self.saveSimpleKey();
        self.simple_key_allowed = false;
        const tok = try self.scanFlowScalar(style);
        if (self.flow_level > 0) self.flow_json_key = true;
        try self.enqueue(tok);
    }

    fn fetchPlainScalar(self: *Self) Error!void {
        try self.saveSimpleKey();
        self.simple_key_allowed = false;
        const tok = try self.scanPlainScalar();
        try self.enqueue(tok);
    }

    // ── directives ──────────────────────────────────────────────────────────

    fn scanDirective(self: *Self) Error!Token {
        const start = self.mark();
        self.skip(); // '%'
        const name = try self.scanDirectiveName();
        var tok: Token = undefined;
        if (std.mem.eql(u8, name, "YAML")) {
            const v = try self.scanVersionDirectiveValue();
            tok = .{ .kind = .version_directive, .start = start, .major = v[0], .minor = v[1] };
        } else if (std.mem.eql(u8, name, "TAG")) {
            while (self.blankAt(0)) self.skip();
            const handle = try self.scanTagHandle(true);
            while (self.blankAt(0)) self.skip();
            if (self.blankzAt(0)) return self.fail("could not find expected tag prefix");
            const prefix = try self.scanTagUri(true, true);
            if (prefix.len == 0) return self.fail("could not find expected tag prefix");
            tok = .{ .kind = .tag_directive, .start = start, .handle = handle, .suffix = prefix };
        } else {
            // Unknown directives are reserved; skip the rest of the line.
            while (!self.breakzAt(0)) self.skip();
            tok = .{ .kind = .version_directive, .start = start, .major = 0, .minor = 0 };
            // Signal "ignore me" with major==0; the parser drops it.
        }
        while (self.blankAt(0)) self.skip();
        if (self.commentHere()) {
            while (!self.breakzAt(0)) self.skip();
        }
        if (!self.breakzAt(0)) return self.fail("did not find expected comment or line break");
        if (self.breakAt(0)) self.skipLine();
        tok.end = self.mark();
        return tok;
    }

    fn scanDirectiveName(self: *Self) Error![]const u8 {
        const s = self.pos;
        while (std.ascii.isAlphanumeric(self.at(0)) or self.at(0) == '-' or self.at(0) == '_') self.skip();
        if (self.pos == s) return self.fail("could not find expected directive name");
        if (!self.blankzAt(0)) return self.fail("found unexpected character in directive name");
        return self.src[s..self.pos];
    }

    fn scanVersionDirectiveValue(self: *Self) Error![2]u32 {
        while (self.blankAt(0)) self.skip();
        const major = try self.scanVersionNumber();
        if (self.at(0) != '.') return self.fail("did not find expected digit or '.' character");
        self.skip();
        const minor = try self.scanVersionNumber();
        return .{ major, minor };
    }

    fn scanVersionNumber(self: *Self) Error!u32 {
        var v: u32 = 0;
        var n: usize = 0;
        while (std.ascii.isDigit(self.at(0))) {
            n += 1;
            if (n > 9) return self.fail("found extremely long version number");
            v = v * 10 + (self.at(0) - '0');
            self.skip();
        }
        if (n == 0) return self.fail("did not find expected version number");
        return v;
    }

    // ── anchors and aliases ─────────────────────────────────────────────────

    fn scanAnchor(self: *Self, kind: TokenKind) Error!Token {
        const start = self.mark();
        self.skip(); // '&' or '*'
        const s = self.pos;
        // ns-anchor-char = ns-char − c-flow-indicator
        while (!self.blankzAt(0) and !isFlowIndicator(self.at(0))) self.skip();
        if (self.pos == s) return self.fail(if (kind == .alias)
            "did not find expected alphabetic or numeric character"
        else
            "did not find expected alphabetic or numeric character");
        const name = self.src[s..self.pos];
        if (!self.blankzAt(0) and !isFlowIndicator(self.at(0)) and self.at(0) != '?' and self.at(0) != ':')
            return self.fail("did not find expected alphabetic or numeric character");
        return .{ .kind = kind, .start = start, .end = self.mark(), .value = name };
    }

    // ── tags ────────────────────────────────────────────────────────────────

    fn scanTag(self: *Self) Error!Token {
        const start = self.mark();
        var handle: []const u8 = "";
        var suffix: []const u8 = "";

        if (self.at(1) == '<') {
            self.skipN(2);
            suffix = try self.scanTagUri(true, false);
            if (self.at(0) != '>') return self.fail("did not find the expected '>'");
            self.skip();
            if (suffix.len == 0) return self.fail("did not find expected tag URI");
        } else {
            const saved = self.saveState();
            handle = try self.scanTagHandle(false);
            if (handle.len > 1 and handle[0] == '!' and handle[handle.len - 1] == '!') {
                suffix = try self.scanTagUri(false, false);
            } else {
                // Not a `!handle!` after all: rewind past the leading `!` and
                // read everything as the suffix of the primary handle.
                self.restoreState(saved);
                self.skip(); // '!'
                suffix = try self.scanTagUri(false, false);
                handle = "!";
            }
        }
        if (!self.blankzAt(0) and !(self.flow_level > 0 and isFlowIndicator(self.at(0))))
            return self.fail("did not find expected whitespace or line break");
        return .{ .kind = .tag, .start = start, .end = self.mark(), .handle = handle, .suffix = suffix };
    }

    const State = struct { pos: usize, line: usize, column: usize };
    fn saveState(self: *const Self) State {
        return .{ .pos = self.pos, .line = self.line, .column = self.column };
    }
    fn restoreState(self: *Self, s: State) void {
        self.pos = s.pos;
        self.line = s.line;
        self.column = s.column;
    }

    fn scanTagHandle(self: *Self, directive: bool) Error![]const u8 {
        if (self.at(0) != '!') return self.fail("did not find expected '!'");
        const s = self.pos;
        self.skip();
        while (std.ascii.isAlphanumeric(self.at(0)) or self.at(0) == '-' or self.at(0) == '_') self.skip();
        if (self.at(0) == '!') {
            self.skip();
        } else if (directive and self.pos != s + 1) {
            return self.fail("did not find expected '!'");
        }
        return self.src[s..self.pos];
    }

    /// `ns-uri-char` with `%XX` unescaping. `allow_flow` keeps `,[]` (legal in
    /// a verbatim tag or a `%TAG` prefix, but flow-terminating in a shorthand).
    fn scanTagUri(self: *Self, allow_flow: bool, directive: bool) Error![]const u8 {
        _ = directive;
        var out: std.ArrayList(u8) = .empty;
        while (true) {
            const c = self.at(0);
            if (c == '%') {
                try self.scanUriEscapes(&out);
                continue;
            }
            const ok = std.ascii.isAlphanumeric(c) or switch (c) {
                ';', '/', '?', ':', '@', '&', '=', '+', '$', '.', '~', '*', '\'', '(', ')', '-', '_', '!' => true,
                ',', '[', ']' => allow_flow,
                else => false,
            };
            if (!ok) break;
            try self.read(&out);
        }
        return out.items;
    }

    fn scanUriEscapes(self: *Self, out: *std.ArrayList(u8)) Error!void {
        while (self.at(0) == '%') {
            const hi = hexVal(self.at(1)) orelse return self.fail("did not find URI escaped octet");
            const lo = hexVal(self.at(2)) orelse return self.fail("did not find URI escaped octet");
            try out.append(self.arena, hi * 16 + lo);
            self.skipN(3);
        }
    }

    fn hexVal(c: u8) ?u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => null,
        };
    }

    // ── block scalars (`|` and `>`) ─────────────────────────────────────────

    fn scanBlockScalar(self: *Self, style: ScalarStyle) Error!Token {
        const literal = style == .literal;
        const start = self.mark();
        self.skip(); // '|' or '>'

        // Header: an optional explicit indentation digit and chomping sign, in
        // either order.
        var chomping: i8 = 0; // 0 clip, +1 keep, -1 strip
        var increment: i64 = 0;
        {
            var i: usize = 0;
            while (i < 2) : (i += 1) {
                const c = self.at(0);
                if (c == '+' or c == '-') {
                    if (chomping != 0) return self.fail("found duplicate chomping indicator");
                    chomping = if (c == '+') 1 else -1;
                    self.skip();
                } else if (c >= '0' and c <= '9') {
                    if (increment != 0) return self.fail("found duplicate indentation indicator");
                    if (c == '0') return self.fail("found an indentation indicator equal to 0");
                    increment = c - '0';
                    self.skip();
                } else break;
            }
        }

        while (self.blankAt(0)) self.skip();
        if (self.commentHere()) while (!self.breakzAt(0)) self.skip();
        if (!self.breakzAt(0)) return self.fail("did not find expected comment or line break");
        if (self.breakAt(0)) {
            self.skipLine();
        } else {
            // The stream ended on the header line itself (`--- |1+`). There is
            // no content line and no line break at all, so nothing survives
            // chomping — not even under `+` (`2G84/02`, `2G84/03`). Returning
            // here is what keeps that case distinct from a trailing *blank
            // line*, which does end in a synthesized break and is kept.
            return .{ .kind = .scalar, .start = start, .end = self.mark(), .value = "", .style = style };
        }

        var indent: i64 = if (increment != 0)
            (if (self.indent >= 0) self.indent + increment else increment)
        else
            0;

        var out: std.ArrayList(u8) = .empty;
        var leading_break: std.ArrayList(u8) = .empty;
        var trailing_breaks: std.ArrayList(u8) = .empty;
        var leading_blank = false;

        try self.scanBlockScalarBreaks(&indent, &trailing_breaks);

        while (@as(i64, @intCast(self.column)) == indent and !self.eof()) {
            // A zero-indented block scalar (`--- >` at the document root) puts
            // content in column 0, where `---`/`...` still end the document.
            if (self.column == 0 and
                ((self.at(0) == '-' and self.at(1) == '-' and self.at(2) == '-') or
                    (self.at(0) == '.' and self.at(1) == '.' and self.at(2) == '.')) and
                self.blankzAt(3)) break;
            const trailing_blank = self.blankAt(0);
            if (!literal and leading_break.items.len > 0 and leading_break.items[0] == '\n' and
                !leading_blank and !trailing_blank)
            {
                if (trailing_breaks.items.len == 0) try out.append(self.arena, ' ');
                leading_break.clearRetainingCapacity();
            } else {
                try out.appendSlice(self.arena, leading_break.items);
                leading_break.clearRetainingCapacity();
            }
            try out.appendSlice(self.arena, trailing_breaks.items);
            trailing_breaks.clearRetainingCapacity();

            leading_blank = self.blankAt(0);
            while (!self.breakzAt(0)) try self.read(&out);
            // YAML 1.2 §5.4: a stream that does not end with a line break is
            // treated as if it did, so the final content line still gets its
            // break (`L24T/01`).
            try leading_break.append(self.arena, '\n');
            if (self.eof()) self.column = 0 else self.skipLine();
            try self.scanBlockScalarBreaks(&indent, &trailing_breaks);
        }

        if (chomping != -1) try out.appendSlice(self.arena, leading_break.items);
        if (chomping == 1) try out.appendSlice(self.arena, trailing_breaks.items);

        return .{
            .kind = .scalar,
            .start = start,
            .end = self.mark(),
            .value = out.items,
            .style = style,
        };
    }

    /// Consume the indentation and empty lines before the next content line,
    /// auto-detecting the block scalar's indentation on the first call when no
    /// explicit indicator was given.
    fn scanBlockScalarBreaks(self: *Self, indent: *i64, breaks: *std.ArrayList(u8)) Error!void {
        const detecting = indent.* == 0;
        var max_indent: i64 = 0;
        while (true) {
            while ((indent.* == 0 or @as(i64, @intCast(self.column)) < indent.*) and self.at(0) == ' ')
                self.skip();
            if (@as(i64, @intCast(self.column)) > max_indent) max_indent = @intCast(self.column);
            // Only meaningful once the indentation is known: while detecting,
            // a tab simply ends the indentation and becomes content (`96NN`).
            if (indent.* != 0 and @as(i64, @intCast(self.column)) < indent.* and self.at(0) == '\t')
                return self.fail("found a tab character where an indentation space is expected");
            if (!self.breakAt(0)) {
                // A stream that ends without a final break is treated as if it
                // had one (§5.4), so a trailing all-blank line still counts as
                // an empty line and `|+` keeps it (`JEF9/02`).
                if (self.eof() and self.column > 0) {
                    try breaks.append(self.arena, '\n');
                    self.column = 0;
                }
                break;
            }
            try self.readLine(breaks);
        }
        if (detecting) {
            // Auto-detected indentation is the deepest leading-space run seen,
            // floored at one past the parent node's indentation. NOT floored
            // at 1: at the document root the parent indent is -1, so a block
            // scalar's content may legitimately start in column 0 (`FP8R`).
            indent.* = @max(max_indent, self.indent + 1);
            // A leading empty line indented deeper than the first content line
            // is an error, not a silently-empty scalar (`S98Z`). The comparison
            // is against `max_indent` — the deepest empty line actually seen —
            // NOT against `indent.*`, whose `self.indent + 1` floor exists for
            // a different purpose. With the floor in the comparison a block
            // scalar that simply has no content at all (`strip: >-` followed by
            // the next mapping key at column 0) looked like a violation
            // (`K858`).
            if (!self.eof()) {
                const col: i64 = @intCast(self.column);
                // Two different faults are possible here, and they need
                // different comparisons.
                //
                // 1. The line we stopped on carries content, and an earlier
                //    *empty* line was indented deeper than it (`S98Z`). The
                //    comparison is against `max_indent` — the deepest empty
                //    line actually seen. Comparing against `indent.*` instead
                //    would also condemn a block scalar that simply has no
                //    content at all, because of the `self.indent + 1` floor
                //    below (`K858`).
                //
                // 2. The line we stopped on is blank to its end, so it is a
                //    leading empty line of the scalar, and we stopped short of
                //    the detected indentation — meaning a tab was offered as
                //    the missing indentation (`Y79Y/000`). Here the floor *is*
                //    the right bound. One space then a tab is fine, because the
                //    space reaches the detected indent (`Y79Y/001`, `R4YG`),
                //    and a tab followed by content is just content (`96NN`).
                if (max_indent > 0 and col < max_indent)
                    return self.fail("found more spaces in a leading empty line than in the first content line");
                if (self.restOfLineBlank() and col < indent.*)
                    return self.fail("found a tab character where an indentation space is expected");
            }
        }
    }

    // ── quoted scalars ──────────────────────────────────────────────────────

    fn scanFlowScalar(self: *Self, style: ScalarStyle) Error!Token {
        const single = style == .single_quoted;
        const start = self.mark();
        self.skip(); // opening quote

        var out: std.ArrayList(u8) = .empty;
        var whitespaces: std.ArrayList(u8) = .empty;
        var leading_break: std.ArrayList(u8) = .empty;
        var trailing_breaks: std.ArrayList(u8) = .empty;

        outer: while (true) {
            if (self.column == 0 and
                ((self.at(0) == '-' and self.at(1) == '-' and self.at(2) == '-') or
                    (self.at(0) == '.' and self.at(1) == '.' and self.at(2) == '.')) and
                self.blankzAt(3))
                return self.fail("found unexpected document indicator");
            if (self.eof()) return self.fail("found unexpected end of stream");

            var leading_blanks = false;
            while (!self.blankzAt(0)) {
                if (single and self.at(0) == '\'' and self.at(1) == '\'') {
                    try out.append(self.arena, '\'');
                    self.skipN(2);
                } else if (self.at(0) == (if (single) @as(u8, '\'') else @as(u8, '"'))) {
                    break;
                } else if (!single and self.at(0) == '\\' and self.breakAt(1)) {
                    self.skip();
                    self.skipLine();
                    leading_blanks = true;
                    break;
                } else if (!single and self.at(0) == '\\') {
                    try self.scanEscape(&out);
                } else {
                    try self.read(&out);
                }
            }
            if (self.at(0) == (if (single) @as(u8, '\'') else @as(u8, '"'))) break :outer;

            while (self.blankAt(0) or self.breakAt(0)) {
                if (self.blankAt(0)) {
                    // A continuation line's indentation is spaces only, so a
                    // tab standing in for it is an error (`DK95/01`).
                    if (leading_blanks and self.at(0) == '\t' and
                        @as(i64, @intCast(self.column)) <= self.indent)
                        return self.fail("found a tab character where an indentation space is expected");
                    if (!leading_blanks) try self.read(&whitespaces) else self.skip();
                } else {
                    if (!leading_blanks) {
                        whitespaces.clearRetainingCapacity();
                        try self.readLine(&leading_break);
                        leading_blanks = true;
                    } else {
                        try self.readLine(&trailing_breaks);
                    }
                }
            }
            // A multi-line quoted scalar must stay indented past its node
            // (`QB6E`); nothing else stops `"a\nb\nc"` at column 0.
            if (leading_blanks and @as(i64, @intCast(self.column)) <= self.indent)
                return self.fail("wrong indentation in a multi-line quoted scalar");

            if (leading_blanks) {
                if (leading_break.items.len > 0 and leading_break.items[0] == '\n') {
                    if (trailing_breaks.items.len == 0) {
                        try out.append(self.arena, ' ');
                    } else {
                        try out.appendSlice(self.arena, trailing_breaks.items);
                        trailing_breaks.clearRetainingCapacity();
                    }
                    leading_break.clearRetainingCapacity();
                } else {
                    try out.appendSlice(self.arena, leading_break.items);
                    try out.appendSlice(self.arena, trailing_breaks.items);
                    leading_break.clearRetainingCapacity();
                    trailing_breaks.clearRetainingCapacity();
                }
            } else {
                try out.appendSlice(self.arena, whitespaces.items);
                whitespaces.clearRetainingCapacity();
            }
        }
        self.skip(); // closing quote

        return .{
            .kind = .scalar,
            .start = start,
            .end = self.mark(),
            .value = out.items,
            .style = style,
        };
    }

    fn scanEscape(self: *Self, out: *std.ArrayList(u8)) Error!void {
        self.skip(); // '\'
        const c = self.at(0);
        var codelen: usize = 0;
        switch (c) {
            '0' => try out.append(self.arena, 0),
            'a' => try out.append(self.arena, 0x07),
            'b' => try out.append(self.arena, 0x08),
            't', '\t' => try out.append(self.arena, 0x09),
            'n' => try out.append(self.arena, 0x0A),
            'v' => try out.append(self.arena, 0x0B),
            'f' => try out.append(self.arena, 0x0C),
            'r' => try out.append(self.arena, 0x0D),
            'e' => try out.append(self.arena, 0x1B),
            ' ' => try out.append(self.arena, 0x20),
            '"' => try out.append(self.arena, '"'),
            '/' => try out.append(self.arena, '/'),
            '\\' => try out.append(self.arena, '\\'),
            'N' => try out.appendSlice(self.arena, "\u{85}"),
            '_' => try out.appendSlice(self.arena, "\u{a0}"),
            'L' => try out.appendSlice(self.arena, "\u{2028}"),
            'P' => try out.appendSlice(self.arena, "\u{2029}"),
            'x' => codelen = 2,
            'u' => codelen = 4,
            'U' => codelen = 8,
            else => return self.fail("found unknown escape character"),
        }
        self.skip();
        if (codelen == 0) return;

        var cp: u32 = 0;
        for (0..codelen) |_| {
            const h = hexVal(self.at(0)) orelse
                return self.fail("did not find expected hexadecimal number");
            cp = cp * 16 + h;
            self.skip();
        }
        if ((cp >= 0xD800 and cp <= 0xDFFF) or cp > 0x10FFFF)
            return self.fail("found invalid Unicode character escape code");
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(cp), &buf) catch
            return self.fail("found invalid Unicode character escape code");
        try out.appendSlice(self.arena, buf[0..n]);
    }

    // ── plain scalars ───────────────────────────────────────────────────────

    fn scanPlainScalar(self: *Self) Error!Token {
        const start = self.mark();
        var end = start;
        const indent: i64 = self.indent + 1;

        var out: std.ArrayList(u8) = .empty;
        var whitespaces: std.ArrayList(u8) = .empty;
        var leading_break: std.ArrayList(u8) = .empty;
        var trailing_breaks: std.ArrayList(u8) = .empty;
        var leading_blanks = false;

        while (true) {
            if (self.column == 0 and
                ((self.at(0) == '-' and self.at(1) == '-' and self.at(2) == '-') or
                    (self.at(0) == '.' and self.at(1) == '.' and self.at(2) == '.')) and
                self.blankzAt(3)) break;
            if (self.at(0) == '#') break;

            while (!self.blankzAt(0)) {
                if (self.at(0) == ':' and
                    (self.blankzAt(1) or (self.flow_level > 0 and isFlowIndicator(self.at(1)))))
                    break;
                if (self.flow_level > 0 and isFlowIndicator(self.at(0))) break;

                if (leading_blanks or whitespaces.items.len > 0) {
                    if (leading_blanks) {
                        if (leading_break.items.len > 0 and leading_break.items[0] == '\n') {
                            if (trailing_breaks.items.len == 0) {
                                try out.append(self.arena, ' ');
                            } else {
                                try out.appendSlice(self.arena, trailing_breaks.items);
                                trailing_breaks.clearRetainingCapacity();
                            }
                            leading_break.clearRetainingCapacity();
                        } else {
                            try out.appendSlice(self.arena, leading_break.items);
                            try out.appendSlice(self.arena, trailing_breaks.items);
                            leading_break.clearRetainingCapacity();
                            trailing_breaks.clearRetainingCapacity();
                        }
                        leading_blanks = false;
                    } else {
                        try out.appendSlice(self.arena, whitespaces.items);
                        whitespaces.clearRetainingCapacity();
                    }
                }
                try self.read(&out);
                end = self.mark();
            }

            if (!(self.blankAt(0) or self.breakAt(0))) break;

            while (self.blankAt(0) or self.breakAt(0)) {
                if (self.blankAt(0)) {
                    // A tab cannot stand in for indentation — but a line that
                    // holds *nothing* but blanks is an empty line, and its
                    // blanks are not indentation of anything, so a tab there is
                    // fine (`DK95/04`).
                    if (leading_blanks and @as(i64, @intCast(self.column)) < indent and
                        self.at(0) == '\t' and !self.restOfLineBlank())
                        return self.fail("found a tab character that violates indentation");
                    if (!leading_blanks) try self.read(&whitespaces) else self.skip();
                } else {
                    if (!leading_blanks) {
                        whitespaces.clearRetainingCapacity();
                        try self.readLine(&leading_break);
                        leading_blanks = true;
                    } else {
                        try self.readLine(&trailing_breaks);
                    }
                }
            }

            if (self.flow_level == 0 and @as(i64, @intCast(self.column)) < indent) break;
        }

        // A multi-line plain scalar re-enables simple keys (its continuation
        // lines cannot themselves be keys, but the token after it can be).
        if (leading_blanks) self.simple_key_allowed = true;

        return .{
            .kind = .scalar,
            .start = start,
            .end = end,
            .value = out.items,
            .style = .plain,
        };
    }
};
