// SPDX-License-Identifier: MIT
//! YAML 1.2 parser — token stream → event stream (stage 2 of `root.zig`'s
//! pipeline).
//!
//! A flat state machine with an explicit state stack, so nesting depth costs
//! heap, never call stack: a 10 000-deep `[[[[…` cannot overflow the stack.
//! `Scanner` has already resolved indentation into `BlockMappingStart` /
//! `BlockEnd` tokens, so this stage never looks at a column; it only decides
//! which *node* a token begins and where the implicit empty scalars go (the
//! `a:` with no value, the `- ` with no entry, the `? k` with no `:`).
//!
//! Tag resolution lives here too, because `%TAG` handles are document-scoped
//! and directives are tokens: `!!str` becomes `tag:yaml.org,2002:str`, and a
//! handle with no directive is an error rather than a silent pass-through.

const std = @import("std");
const scanner = @import("scanner.zig");

const Scanner = scanner.Scanner;
const Token = scanner.Token;
const TokenKind = scanner.TokenKind;

pub const ScalarStyle = scanner.ScalarStyle;
pub const Mark = scanner.Mark;
pub const Error = scanner.Error;

pub const CollectionStyle = enum { block, flow };

/// One YAML parse event. All slices point into the parser's arena and stay
/// valid until `deinit` — see the lifetime note in `root.zig`.
pub const Event = union(enum) {
    stream_start,
    stream_end,
    document_start: Document,
    document_end: Document,
    alias: Alias,
    scalar: Scalar,
    sequence_start: CollectionStart,
    sequence_end,
    mapping_start: CollectionStart,
    mapping_end,

    pub const Document = struct {
        /// `true` when the document boundary was written out (`---` / `...`).
        explicit: bool,
    };
    pub const Alias = struct { anchor: []const u8 };
    pub const Scalar = struct {
        anchor: ?[]const u8 = null,
        /// The *resolved* tag (`tag:yaml.org,2002:str`, `!local`, `!`), or
        /// null when the node carried no tag shorthand.
        tag: ?[]const u8 = null,
        value: []const u8,
        style: ScalarStyle,
    };
    pub const CollectionStart = struct {
        anchor: ?[]const u8 = null,
        tag: ?[]const u8 = null,
        style: CollectionStyle,
    };
};

const State = enum {
    stream_start,
    implicit_document_start,
    document_start,
    document_content,
    document_end,
    block_node,
    block_node_or_indentless_sequence,
    flow_node,
    block_sequence_first_entry,
    block_sequence_entry,
    indentless_sequence_entry,
    block_mapping_first_key,
    block_mapping_key,
    block_mapping_value,
    flow_sequence_first_entry,
    flow_sequence_entry,
    flow_sequence_entry_mapping_key,
    flow_sequence_entry_mapping_value,
    flow_sequence_entry_mapping_end,
    flow_mapping_first_key,
    flow_mapping_key,
    flow_mapping_value,
    flow_mapping_empty_value,
    end,
};

const TagDirective = struct { handle: []const u8, prefix: []const u8 };

/// Bound on the state stack — the parser is iterative, so this only caps
/// memory, and matches the scanner's own nesting cap.
const max_depth = scanner.max_depth;

pub const Parser = struct {
    arena_state: std.heap.ArenaAllocator,
    src: []const u8,
    /// Both are bound on the first `next()` call, once `self` has a stable
    /// address (the arena allocator captures `&arena_state`).
    arena: std.mem.Allocator = undefined,
    scan: Scanner = undefined,
    started: bool = false,

    state: State = .stream_start,
    states: std.ArrayList(State) = .empty,
    tag_directives: std.ArrayList(TagDirective) = .empty,
    /// Set once the stream has ended or errored; `next` then keeps returning
    /// null / the same error rather than walking off the end.
    done: bool = false,

    /// Progress accounting for the bound in `next()`.
    last_token_count: usize = 0,
    events_since_token: usize = 0,

    /// The stream is at a "between documents" position: either nothing has been
    /// parsed yet, or the last document was closed by an explicit `...`. See
    /// `parseDocumentStart`.
    footer_seen: bool = true,

    problem: []const u8 = "",
    problem_mark: Mark = .{},

    const Self = @This();

    /// `src` is borrowed, not copied — it must outlive the parser.
    pub fn init(gpa: std.mem.Allocator, src: []const u8) Self {
        return .{ .arena_state = std.heap.ArenaAllocator.init(gpa), .src = src };
    }

    pub fn deinit(self: *Self) void {
        self.arena_state.deinit();
    }

    /// Yields the next event, or null once `stream_end` has been delivered.
    pub fn next(self: *Self) Error!?Event {
        if (!self.started) {
            self.arena = self.arena_state.allocator();
            self.scan = Scanner.init(self.arena, self.src);
            self.started = true;
        }
        if (self.done) return null;
        if (self.state == .end) {
            self.done = true;
            return null;
        }
        // Parser-side progress bound. The scanner is monotone (see its `peek`),
        // but a state machine can still cycle *without* consuming tokens: every
        // token-free event is an implicit empty scalar or a collection close,
        // and each of those must strictly shrink the state stack. The stack is
        // bounded by `max_depth`, so a run of token-free events longer than
        // that is necessarily a cycle, not a legal document. This is that
        // invariant made checkable rather than an arbitrary iteration cap.
        const consumed = self.scan.tokens_parsed;
        if (consumed != self.last_token_count) {
            self.last_token_count = consumed;
            self.events_since_token = 0;
        } else {
            self.events_since_token += 1;
            if (self.events_since_token > max_depth + 8) {
                self.done = true;
                return self.fail("parser made no progress", self.problem_mark);
            }
        }
        const ev = self.stateMachine() catch |e| {
            self.done = true;
            if (self.problem.len == 0) {
                self.problem = self.scan.problem;
                self.problem_mark = self.scan.problem_mark;
            }
            return e;
        };
        return ev;
    }

    fn fail(self: *Self, msg: []const u8, m: Mark) Error {
        if (self.problem.len == 0) {
            self.problem = msg;
            self.problem_mark = m;
        }
        return error.InvalidYaml;
    }

    fn pushState(self: *Self, s: State) Error!void {
        if (self.states.items.len >= max_depth) return self.fail("exceeded maximum nesting depth", .{});
        try self.states.append(self.arena, s);
    }

    fn popState(self: *Self) State {
        return self.states.pop() orelse .end;
    }

    fn stateMachine(self: *Self) Error!Event {
        return switch (self.state) {
            .stream_start => self.parseStreamStart(),
            .implicit_document_start => self.parseDocumentStart(true),
            .document_start => self.parseDocumentStart(false),
            .document_content => self.parseDocumentContent(),
            .document_end => self.parseDocumentEnd(),
            .block_node => self.parseNode(true, false),
            .block_node_or_indentless_sequence => self.parseNode(true, true),
            .flow_node => self.parseNode(false, false),
            .block_sequence_first_entry => self.parseBlockSequenceEntry(true),
            .block_sequence_entry => self.parseBlockSequenceEntry(false),
            .indentless_sequence_entry => self.parseIndentlessSequenceEntry(),
            .block_mapping_first_key => self.parseBlockMappingKey(true),
            .block_mapping_key => self.parseBlockMappingKey(false),
            .block_mapping_value => self.parseBlockMappingValue(),
            .flow_sequence_first_entry => self.parseFlowSequenceEntry(true),
            .flow_sequence_entry => self.parseFlowSequenceEntry(false),
            .flow_sequence_entry_mapping_key => self.parseFlowSequenceEntryMappingKey(),
            .flow_sequence_entry_mapping_value => self.parseFlowSequenceEntryMappingValue(),
            .flow_sequence_entry_mapping_end => self.parseFlowSequenceEntryMappingEnd(),
            .flow_mapping_first_key => self.parseFlowMappingKey(true),
            .flow_mapping_key => self.parseFlowMappingKey(false),
            .flow_mapping_value => self.parseFlowMappingValue(false),
            .flow_mapping_empty_value => self.parseFlowMappingValue(true),
            .end => unreachable,
        };
    }

    fn peek(self: *Self) Error!*Token {
        return self.scan.peek();
    }
    fn skip(self: *Self) Error!void {
        _ = try self.scan.next();
    }

    fn emptyScalar() Event {
        return .{ .scalar = .{ .value = "", .style = .plain } };
    }

    // ── stream / document framing ───────────────────────────────────────────

    fn parseStreamStart(self: *Self) Error!Event {
        const tok = try self.peek();
        if (tok.kind != .stream_start) return self.fail("did not find expected <stream-start>", tok.start);
        try self.skip();
        self.state = .implicit_document_start;
        return .stream_start;
    }

    /// YAML 1.2 §9.1: a **bare** document (one with no `---`) and a directive
    /// document may only appear where the stream is "between documents" — at
    /// the very start, or after an explicit `...` footer. After a document that
    /// ended implicitly, neither is allowed.
    ///
    /// Both halves of that rule are load-bearing in the suite: `HWV9`/`QT73`
    /// need a lone `...` to be a legal no-op, `7Z25` needs a bare document to
    /// follow one, and `9HCY`/`EB22`/`RHX7` need directives *without* a
    /// preceding footer to be rejected.
    fn parseDocumentStart(self: *Self, implicit: bool) Error!Event {
        var tok = try self.peek();
        // Stray `...` markers are not documents — consume them, and each one
        // re-opens the between-documents position.
        while (tok.kind == .document_end) {
            self.footer_seen = true;
            try self.skip();
            tok = try self.peek();
        }

        const between_documents = implicit or self.footer_seen;

        if (between_documents and tok.kind != .version_directive and tok.kind != .tag_directive and
            tok.kind != .document_start and tok.kind != .stream_end)
        {
            try self.applyDefaultTagDirectives();
            try self.pushState(.document_end);
            self.state = .block_node;
            self.footer_seen = false;
            return .{ .document_start = .{ .explicit = false } };
        }

        if (tok.kind != .stream_end) {
            if (!between_documents and
                (tok.kind == .version_directive or tok.kind == .tag_directive))
                return self.fail("directives must be preceded by a document end marker", tok.start);
            self.footer_seen = false;
            try self.processDirectives();
            tok = try self.peek();
            if (tok.kind != .document_start)
                return self.fail("did not find expected <document start>", tok.start);
            try self.pushState(.document_end);
            self.state = .document_content;
            try self.skip();
            return .{ .document_start = .{ .explicit = true } };
        }

        try self.skip();
        self.state = .end;
        return .stream_end;
    }

    fn parseDocumentContent(self: *Self) Error!Event {
        const tok = try self.peek();
        switch (tok.kind) {
            .version_directive, .tag_directive, .document_start, .document_end, .stream_end => {
                self.state = self.popState();
                return emptyScalar();
            },
            else => return self.parseNode(true, false),
        }
    }

    fn parseDocumentEnd(self: *Self) Error!Event {
        const tok = try self.peek();
        var explicit = false;
        if (tok.kind == .document_end) {
            try self.skip();
            explicit = true;
        }
        self.tag_directives.clearRetainingCapacity();
        self.state = .document_start;
        // Only an explicit `...` re-opens the between-documents position.
        self.footer_seen = explicit;
        return .{ .document_end = .{ .explicit = explicit } };
    }

    // ── nodes ───────────────────────────────────────────────────────────────

    fn parseNode(self: *Self, block: bool, indentless_sequence: bool) Error!Event {
        var tok = try self.peek();

        if (tok.kind == .alias) {
            const name = tok.value;
            try self.skip();
            self.state = self.popState();
            return .{ .alias = .{ .anchor = name } };
        }

        var anchor: ?[]const u8 = null;
        var handle: ?[]const u8 = null;
        var suffix: []const u8 = "";
        var tag_mark: Mark = tok.start;

        if (tok.kind == .anchor) {
            anchor = tok.value;
            try self.skip();
            tok = try self.peek();
            if (tok.kind == .tag) {
                handle = tok.handle;
                suffix = tok.suffix;
                tag_mark = tok.start;
                try self.skip();
                tok = try self.peek();
            }
        } else if (tok.kind == .tag) {
            handle = tok.handle;
            suffix = tok.suffix;
            tag_mark = tok.start;
            try self.skip();
            tok = try self.peek();
            if (tok.kind == .anchor) {
                anchor = tok.value;
                try self.skip();
                tok = try self.peek();
            }
        }

        const tag: ?[]const u8 = if (handle) |h| try self.resolveTag(h, suffix, tag_mark) else null;

        if (indentless_sequence and tok.kind == .block_entry) {
            self.state = .indentless_sequence_entry;
            return .{ .sequence_start = .{ .anchor = anchor, .tag = tag, .style = .block } };
        }

        switch (tok.kind) {
            .scalar => {
                const v = tok.value;
                const st = tok.style;
                try self.skip();
                self.state = self.popState();
                return .{ .scalar = .{ .anchor = anchor, .tag = tag, .value = v, .style = st } };
            },
            .flow_sequence_start => {
                self.state = .flow_sequence_first_entry;
                return .{ .sequence_start = .{ .anchor = anchor, .tag = tag, .style = .flow } };
            },
            .flow_mapping_start => {
                self.state = .flow_mapping_first_key;
                return .{ .mapping_start = .{ .anchor = anchor, .tag = tag, .style = .flow } };
            },
            .block_sequence_start => if (block) {
                self.state = .block_sequence_first_entry;
                return .{ .sequence_start = .{ .anchor = anchor, .tag = tag, .style = .block } };
            },
            .block_mapping_start => if (block) {
                self.state = .block_mapping_first_key;
                return .{ .mapping_start = .{ .anchor = anchor, .tag = tag, .style = .block } };
            },
            else => {},
        }

        if (anchor != null or tag != null) {
            self.state = self.popState();
            return .{ .scalar = .{ .anchor = anchor, .tag = tag, .value = "", .style = .plain } };
        }
        return self.fail("did not find expected node content", tok.start);
    }

    // ── block collections ───────────────────────────────────────────────────

    fn parseBlockSequenceEntry(self: *Self, first: bool) Error!Event {
        if (first) try self.skip();
        const tok = try self.peek();
        if (tok.kind == .block_entry) {
            try self.skip();
            const nxt = try self.peek();
            if (nxt.kind != .block_entry and nxt.kind != .block_end) {
                try self.pushState(.block_sequence_entry);
                return self.parseNode(true, false);
            }
            self.state = .block_sequence_entry;
            return emptyScalar();
        }
        if (tok.kind == .block_end) {
            try self.skip();
            self.state = self.popState();
            return .sequence_end;
        }
        return self.fail("did not find expected '-' indicator", tok.start);
    }

    fn parseIndentlessSequenceEntry(self: *Self) Error!Event {
        const tok = try self.peek();
        if (tok.kind == .block_entry) {
            try self.skip();
            const nxt = try self.peek();
            switch (nxt.kind) {
                .block_entry, .key, .value, .block_end => {
                    self.state = .indentless_sequence_entry;
                    return emptyScalar();
                },
                else => {
                    try self.pushState(.indentless_sequence_entry);
                    return self.parseNode(true, false);
                },
            }
        }
        self.state = self.popState();
        return .sequence_end;
    }

    fn parseBlockMappingKey(self: *Self, first: bool) Error!Event {
        if (first) try self.skip();
        const tok = try self.peek();
        if (tok.kind == .key) {
            try self.skip();
            const nxt = try self.peek();
            switch (nxt.kind) {
                .key, .value, .block_end => {
                    self.state = .block_mapping_value;
                    return emptyScalar();
                },
                else => {
                    try self.pushState(.block_mapping_value);
                    return self.parseNode(true, true);
                },
            }
        }
        if (tok.kind == .value) {
            self.state = .block_mapping_value;
            return emptyScalar();
        }
        if (tok.kind == .block_end) {
            try self.skip();
            self.state = self.popState();
            return .mapping_end;
        }
        return self.fail("did not find expected key", tok.start);
    }

    fn parseBlockMappingValue(self: *Self) Error!Event {
        const tok = try self.peek();
        if (tok.kind == .value) {
            try self.skip();
            const nxt = try self.peek();
            switch (nxt.kind) {
                .key, .value, .block_end => {
                    self.state = .block_mapping_key;
                    return emptyScalar();
                },
                else => {
                    try self.pushState(.block_mapping_key);
                    return self.parseNode(true, true);
                },
            }
        }
        self.state = .block_mapping_key;
        return emptyScalar();
    }

    // ── flow collections ────────────────────────────────────────────────────

    fn parseFlowSequenceEntry(self: *Self, first: bool) Error!Event {
        if (first) try self.skip();
        var tok = try self.peek();
        if (tok.kind != .flow_sequence_end) {
            if (!first) {
                if (tok.kind == .flow_entry) {
                    try self.skip();
                    tok = try self.peek();
                } else {
                    return self.fail("did not find expected ',' or ']'", tok.start);
                }
            }
            // `[? a : b]` opens a single-pair mapping with an explicit key;
            // `[: v]` opens one whose key is *empty*. In the second case the
            // scanner emits a bare `value` token with no `key` before it (there
            // was no simple key to promote), so the `:` must be left in place
            // for `flow_sequence_entry_mapping_value` to consume (`CFD4`).
            if (tok.kind == .key or tok.kind == .value) {
                self.state = .flow_sequence_entry_mapping_key;
                if (tok.kind == .key) try self.skip();
                return .{ .mapping_start = .{ .style = .flow } };
            }
            if (tok.kind != .flow_sequence_end) {
                try self.pushState(.flow_sequence_entry);
                return self.parseNode(false, false);
            }
        }
        try self.skip();
        self.state = self.popState();
        return .sequence_end;
    }

    fn parseFlowSequenceEntryMappingKey(self: *Self) Error!Event {
        const tok = try self.peek();
        switch (tok.kind) {
            .value, .flow_entry, .flow_sequence_end => {
                self.state = .flow_sequence_entry_mapping_value;
                return emptyScalar();
            },
            else => {
                try self.pushState(.flow_sequence_entry_mapping_value);
                return self.parseNode(false, false);
            },
        }
    }

    fn parseFlowSequenceEntryMappingValue(self: *Self) Error!Event {
        const tok = try self.peek();
        if (tok.kind == .value) {
            try self.skip();
            const nxt = try self.peek();
            if (nxt.kind != .flow_entry and nxt.kind != .flow_sequence_end) {
                try self.pushState(.flow_sequence_entry_mapping_end);
                return self.parseNode(false, false);
            }
        }
        self.state = .flow_sequence_entry_mapping_end;
        return emptyScalar();
    }

    fn parseFlowSequenceEntryMappingEnd(self: *Self) Error!Event {
        self.state = .flow_sequence_entry;
        return .mapping_end;
    }

    fn parseFlowMappingKey(self: *Self, first: bool) Error!Event {
        if (first) try self.skip();
        var tok = try self.peek();
        if (tok.kind != .flow_mapping_end) {
            if (!first) {
                if (tok.kind == .flow_entry) {
                    try self.skip();
                    tok = try self.peek();
                } else {
                    return self.fail("did not find expected ',' or '}'", tok.start);
                }
            }
            if (tok.kind == .key) {
                try self.skip();
                const nxt = try self.peek();
                switch (nxt.kind) {
                    .value, .flow_entry, .flow_mapping_end => {
                        self.state = .flow_mapping_value;
                        return emptyScalar();
                    },
                    else => {
                        try self.pushState(.flow_mapping_value);
                        return self.parseNode(false, false);
                    },
                }
            }
            // `{: v}` / `{ : }` — an empty key. As in a flow sequence the
            // scanner has no simple key to promote, so it emits `value`
            // directly; the empty scalar key is synthesized here and the `:`
            // left for `flow_mapping_value` (`FRK4`, `NKF9`).
            if (tok.kind == .value) {
                self.state = .flow_mapping_value;
                return emptyScalar();
            }
            if (tok.kind != .flow_mapping_end) {
                try self.pushState(.flow_mapping_empty_value);
                return self.parseNode(false, false);
            }
        }
        try self.skip();
        self.state = self.popState();
        return .mapping_end;
    }

    fn parseFlowMappingValue(self: *Self, empty: bool) Error!Event {
        if (empty) {
            self.state = .flow_mapping_key;
            return emptyScalar();
        }
        const tok = try self.peek();
        if (tok.kind == .value) {
            try self.skip();
            const nxt = try self.peek();
            if (nxt.kind != .flow_entry and nxt.kind != .flow_mapping_end) {
                try self.pushState(.flow_mapping_key);
                return self.parseNode(false, false);
            }
        }
        self.state = .flow_mapping_key;
        return emptyScalar();
    }

    // ── directives ──────────────────────────────────────────────────────────

    fn applyDefaultTagDirectives(self: *Self) Error!void {
        try self.addDefault("!", "!");
        try self.addDefault("!!", "tag:yaml.org,2002:");
    }

    fn addDefault(self: *Self, handle: []const u8, prefix: []const u8) Error!void {
        for (self.tag_directives.items) |d| {
            if (std.mem.eql(u8, d.handle, handle)) return;
        }
        try self.tag_directives.append(self.arena, .{ .handle = handle, .prefix = prefix });
    }

    fn processDirectives(self: *Self) Error!void {
        var version_seen = false;
        while (true) {
            const tok = try self.peek();
            switch (tok.kind) {
                .version_directive => {
                    // major == 0 marks a reserved/unknown directive the
                    // scanner skipped; those are ignored, not rejected.
                    if (tok.major != 0) {
                        if (version_seen)
                            return self.fail("found duplicate %YAML directive", tok.start);
                        // YAML 1.2 §6.8.1: a *minor* version we do not know is
                        // a warning, not an error — the document is parsed as
                        // 1.2 anyway (`BEC7` parses `%YAML 1.3`). Only a
                        // different major version is fatal.
                        if (tok.major != 1)
                            return self.fail("found incompatible YAML document", tok.start);
                        version_seen = true;
                    }
                    try self.skip();
                },
                .tag_directive => {
                    const handle = tok.handle;
                    const prefix = tok.suffix;
                    const start = tok.start;
                    for (self.tag_directives.items) |d| {
                        if (std.mem.eql(u8, d.handle, handle))
                            return self.fail("found duplicate %TAG directive", start);
                    }
                    try self.tag_directives.append(self.arena, .{ .handle = handle, .prefix = prefix });
                    try self.skip();
                },
                else => break,
            }
        }
        try self.applyDefaultTagDirectives();
    }

    fn resolveTag(self: *Self, handle: []const u8, suffix: []const u8, m: Mark) Error![]const u8 {
        if (handle.len == 0) return suffix; // verbatim `!<…>`
        for (self.tag_directives.items) |d| {
            if (std.mem.eql(u8, d.handle, handle)) {
                if (suffix.len == 0) return d.prefix;
                return std.mem.concat(self.arena, u8, &.{ d.prefix, suffix }) catch return error.OutOfMemory;
            }
        }
        return self.fail("found undefined tag handle", m);
    }
};
