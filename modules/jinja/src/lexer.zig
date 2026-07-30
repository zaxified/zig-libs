// SPDX-License-Identifier: MIT
//! Source bytes → a flat list of chunks: literal text, `{{ … }}` output tags
//! and `{% … %}` statement tags, with tag interiors already tokenized.
//!
//! Splitting the source into chunks *before* parsing is what makes whitespace
//! control tractable: `{%-`/`-%}`, `trim_blocks` and `lstrip_blocks` all edit
//! the text chunk on one side of a tag, and doing that as a pass over a chunk
//! list is a handful of slice edits instead of a rule threaded through the
//! parser. `{% raw %}` is resolved here too — its body must never be tokenized.

const std = @import("std");

pub const Options = struct {
    /// Remove the first newline after a *statement* or comment tag (never after
    /// an output tag — that asymmetry is the reference implementation's).
    trim_blocks: bool = false,
    /// Strip leading whitespace from the start of a line to a statement or
    /// comment tag.
    lstrip_blocks: bool = false,
    /// Keep the single trailing newline that a template file almost always
    /// ends with. Off by default, matching the reference.
    keep_trailing_newline: bool = false,
};

pub const Error = error{ OutOfMemory, TemplateSyntaxError };

pub const Kind = enum {
    name,
    string,
    integer,
    float,
    add,
    sub,
    mul,
    div,
    floordiv,
    mod,
    pow,
    tilde,
    lparen,
    rparen,
    lbracket,
    rbracket,
    lbrace,
    rbrace,
    eq,
    ne,
    lt,
    le,
    gt,
    ge,
    assign,
    dot,
    comma,
    colon,
    pipe,
};

pub const Token = struct {
    kind: Kind,
    /// For `.name` the identifier; for `.string` the **decoded** contents.
    text: []const u8 = "",
    int: i64 = 0,
    float: f64 = 0,
    line: usize = 1,

    pub fn isName(self: Token, n: []const u8) bool {
        return self.kind == .name and std.mem.eql(u8, self.text, n);
    }
};

pub const Chunk = union(enum) {
    text: []const u8,
    /// `{{ … }}`
    output: []const Token,
    /// `{% … %}`
    stmt: []const Token,
};

pub const Piece = struct {
    chunk: Chunk,
    line: usize,
};

/// A tag's whitespace-control intent, recorded while scanning and applied in
/// one pass afterwards. `before`/`after` are indices of the text pieces on
/// either side of the tag — not of the tag itself, which is what makes the
/// application a plain slice edit.
const Mark = struct {
    before: ?usize,
    after: usize,
    block: bool,
    strip_before: bool,
    plus_before: bool,
    strip_after: bool,
    plus_after: bool,
};

pub const Result = struct {
    pieces: []const Piece,
};

pub const Diagnostic = @import("diag.zig").Diagnostic;

pub fn lex(arena: std.mem.Allocator, source: []const u8, opts: Options, diag: *Diagnostic) Error!Result {
    var l: Lexer = .{
        .arena = arena,
        .src = source,
        .opts = opts,
        .diag = diag,
    };
    if (!opts.keep_trailing_newline) {
        if (std.mem.endsWith(u8, l.src, "\r\n")) {
            l.src = l.src[0 .. l.src.len - 2];
        } else if (std.mem.endsWith(u8, l.src, "\n")) {
            l.src = l.src[0 .. l.src.len - 1];
        }
    }
    try l.run();
    l.applyWhitespace();
    return .{ .pieces = l.pieces.items };
}

const Lexer = struct {
    arena: std.mem.Allocator,
    src: []const u8,
    pos: usize = 0,
    line: usize = 1,
    opts: Options,
    diag: *Diagnostic,
    pieces: std.ArrayList(Piece) = .empty,
    marks: std.ArrayList(Mark) = .empty,

    fn fail(self: *Lexer, comptime msg: []const u8) Error {
        self.diag.set(self.line, "{s}", .{msg});
        return error.TemplateSyntaxError;
    }

    fn countLines(self: *Lexer, s: []const u8) void {
        for (s) |c| if (c == '\n') {
            self.line += 1;
        };
    }

    fn run(self: *Lexer) Error!void {
        while (self.pos < self.src.len) {
            const start = self.pos;
            const next = findTagStart(self.src, self.pos);
            if (next == null) {
                try self.pushText(self.src[start..]);
                self.pos = self.src.len;
                break;
            }
            const at = next.?;
            if (at > start) try self.pushText(self.src[start..at]);
            self.pos = at;
            switch (self.src[at + 1]) {
                '#' => try self.lexComment(),
                '{' => try self.lexTag(false),
                '%' => try self.lexTag(true),
                else => unreachable,
            }
        }
    }

    fn pushText(self: *Lexer, t: []const u8) Error!void {
        try self.pieces.append(self.arena, .{ .chunk = .{ .text = t }, .line = self.line });
        self.countLines(t);
    }

    fn priorText(self: *Lexer) ?usize {
        return if (self.pieces.items.len > 0) self.pieces.items.len - 1 else null;
    }

    /// `{# … #}` — dropped entirely, but its whitespace control still applies
    /// to the text on both sides.
    fn lexComment(self: *Lexer) Error!void {
        var p = self.pos + 2;
        var strip_before = false;
        var plus_before = false;
        if (p < self.src.len and self.src[p] == '-') {
            strip_before = true;
            p += 1;
        } else if (p < self.src.len and self.src[p] == '+') {
            plus_before = true;
            p += 1;
        }
        const end = std.mem.indexOfPos(u8, self.src, p, "#}") orelse return self.fail("unclosed comment");
        var body_end = end;
        var strip_after = false;
        var plus_after = false;
        if (body_end > p and self.src[body_end - 1] == '-') {
            strip_after = true;
            body_end -= 1;
        } else if (body_end > p and self.src[body_end - 1] == '+') {
            plus_after = true;
            body_end -= 1;
        }
        try self.marks.append(self.arena, .{
            .before = self.priorText(),
            .after = self.pieces.items.len,
            .block = true,
            .strip_before = strip_before,
            .plus_before = plus_before,
            .strip_after = strip_after,
            .plus_after = plus_after,
        });
        self.countLines(self.src[self.pos .. end + 2]);
        self.pos = end + 2;
    }

    fn lexTag(self: *Lexer, block: bool) Error!void {
        const tag_line = self.line;
        var p = self.pos + 2;
        var strip_before = false;
        var plus_before = false;
        if (p < self.src.len and self.src[p] == '-') {
            strip_before = true;
            p += 1;
        } else if (p < self.src.len and self.src[p] == '+') {
            plus_before = true;
            p += 1;
        }

        var toks: std.ArrayList(Token) = .empty;
        var depth: usize = 0;
        var strip_after = false;
        var plus_after = false;

        while (true) {
            // whitespace
            while (p < self.src.len and isSpace(self.src[p])) : (p += 1) {
                if (self.src[p] == '\n') self.line += 1;
            }
            if (p >= self.src.len) return self.fail("unclosed tag");

            const c = self.src[p];
            // tag end?
            if (depth == 0) {
                if ((c == '-' or c == '+') and p + 2 < self.src.len and
                    ((block and self.src[p + 1] == '%' and self.src[p + 2] == '}') or
                        (!block and self.src[p + 1] == '}' and self.src[p + 2] == '}')))
                {
                    if (c == '-') strip_after = true else plus_after = true;
                    p += 3;
                    break;
                }
                if (block and c == '%' and p + 1 < self.src.len and self.src[p + 1] == '}') {
                    p += 2;
                    break;
                }
                if (!block and c == '}' and p + 1 < self.src.len and self.src[p + 1] == '}') {
                    p += 2;
                    break;
                }
            }
            const tok = try self.lexToken(&p, &depth);
            try toks.append(self.arena, tok);
        }

        self.pos = p;
        const before = self.priorText();

        // `{% raw %}` swallows its body verbatim.
        if (block and toks.items.len == 1 and toks.items[0].isName("raw")) {
            try self.lexRaw(tag_line, before, strip_before, plus_before, strip_after, plus_after);
            return;
        }

        try self.pieces.append(self.arena, .{
            .chunk = if (block) .{ .stmt = toks.items } else .{ .output = toks.items },
            .line = tag_line,
        });
        try self.marks.append(self.arena, .{
            .before = before,
            .after = self.pieces.items.len,
            .block = block,
            .strip_before = strip_before,
            .plus_before = plus_before,
            .strip_after = strip_after,
            .plus_after = plus_after,
        });
    }

    /// Everything up to the next `{% endraw %}` is literal text. Scanned as
    /// bytes — a `{{` or `{%` inside a raw block is data, not a tag.
    fn lexRaw(
        self: *Lexer,
        tag_line: usize,
        open_before: ?usize,
        open_strip: bool,
        open_plus: bool,
        open_strip_after: bool,
        open_plus_after: bool,
    ) Error!void {
        var scan = self.pos;
        while (true) {
            const open = std.mem.indexOfPos(u8, self.src, scan, "{%") orelse
                return self.fail("unclosed {% raw %}");
            var q = open + 2;
            var strip_before = false;
            var plus_before = false;
            if (q < self.src.len and (self.src[q] == '-' or self.src[q] == '+')) {
                strip_before = self.src[q] == '-';
                plus_before = self.src[q] == '+';
                q += 1;
            }
            while (q < self.src.len and isSpace(self.src[q])) q += 1;
            if (!std.mem.startsWith(u8, self.src[q..], "endraw")) {
                scan = open + 2;
                continue;
            }
            q += "endraw".len;
            while (q < self.src.len and isSpace(self.src[q])) q += 1;
            var strip_after = false;
            var plus_after = false;
            if (q < self.src.len and (self.src[q] == '-' or self.src[q] == '+')) {
                strip_after = self.src[q] == '-';
                plus_after = self.src[q] == '+';
                q += 1;
            }
            if (!std.mem.startsWith(u8, self.src[q..], "%}")) return self.fail("malformed {% endraw %}");
            q += 2;

            const body = self.src[self.pos..open];
            const body_idx = self.pieces.items.len;
            try self.pieces.append(self.arena, .{ .chunk = .{ .text = body }, .line = tag_line });
            self.countLines(self.src[self.pos..q]);
            try self.marks.append(self.arena, .{
                .before = open_before,
                .after = body_idx,
                .block = true,
                .strip_before = open_strip,
                .plus_before = open_plus,
                .strip_after = open_strip_after,
                .plus_after = open_plus_after,
            });
            try self.marks.append(self.arena, .{
                .before = body_idx,
                .after = self.pieces.items.len,
                .block = true,
                .strip_before = strip_before,
                .plus_before = plus_before,
                .strip_after = strip_after,
                .plus_after = plus_after,
            });
            self.pos = q;
            return;
        }
    }

    fn lexToken(self: *Lexer, p: *usize, depth: *usize) Error!Token {
        const s = self.src;
        const c = s[p.*];
        const line = self.line;
        if (c == '"' or c == '\'') return self.lexString(p);
        if (std.ascii.isDigit(c)) return self.lexNumber(p);
        if (c == '_' or std.ascii.isAlphabetic(c)) {
            const start = p.*;
            while (p.* < s.len and (s[p.*] == '_' or std.ascii.isAlphanumeric(s[p.*]))) p.* += 1;
            return .{ .kind = .name, .text = s[start..p.*], .line = line };
        }

        const two: []const u8 = if (p.* + 1 < s.len) s[p.* .. p.* + 2] else "";
        const pairs = .{
            .{ "**", Kind.pow },
            .{ "//", Kind.floordiv },
            .{ "==", Kind.eq },
            .{ "!=", Kind.ne },
            .{ "<=", Kind.le },
            .{ ">=", Kind.ge },
        };
        inline for (pairs) |pr| {
            if (std.mem.eql(u8, two, pr[0])) {
                p.* += 2;
                return .{ .kind = pr[1], .line = line };
            }
        }
        const one: Kind = switch (c) {
            '+' => .add,
            '-' => .sub,
            '*' => .mul,
            '/' => .div,
            '%' => .mod,
            '~' => .tilde,
            '(' => .lparen,
            ')' => .rparen,
            '[' => .lbracket,
            ']' => .rbracket,
            '{' => .lbrace,
            '}' => .rbrace,
            '<' => .lt,
            '>' => .gt,
            '=' => .assign,
            '.' => .dot,
            ',' => .comma,
            ':' => .colon,
            '|' => .pipe,
            else => return self.fail("unexpected character in tag"),
        };
        switch (one) {
            .lparen, .lbracket, .lbrace => depth.* += 1,
            .rparen, .rbracket, .rbrace => {
                if (depth.* == 0) return self.fail("unbalanced bracket");
                depth.* -= 1;
            },
            else => {},
        }
        p.* += 1;
        return .{ .kind = one, .line = line };
    }

    fn lexString(self: *Lexer, p: *usize) Error!Token {
        const s = self.src;
        const quote = s[p.*];
        const line = self.line;
        var out: std.ArrayList(u8) = .empty;
        var i = p.* + 1;
        while (true) {
            if (i >= s.len) return self.fail("unterminated string literal");
            const c = s[i];
            if (c == quote) {
                i += 1;
                break;
            }
            if (c == '\\') {
                if (i + 1 >= s.len) return self.fail("unterminated string literal");
                const e = s[i + 1];
                i += 2;
                switch (e) {
                    'n' => try out.append(self.arena, '\n'),
                    't' => try out.append(self.arena, '\t'),
                    'r' => try out.append(self.arena, '\r'),
                    '0' => try out.append(self.arena, 0),
                    '\\' => try out.append(self.arena, '\\'),
                    '\'' => try out.append(self.arena, '\''),
                    '"' => try out.append(self.arena, '"'),
                    'x' => {
                        if (i + 2 > s.len) return self.fail("bad \\x escape");
                        const v = std.fmt.parseInt(u8, s[i .. i + 2], 16) catch return self.fail("bad \\x escape");
                        try out.append(self.arena, v);
                        i += 2;
                    },
                    'u' => {
                        if (i + 4 > s.len) return self.fail("bad \\u escape");
                        const v = std.fmt.parseInt(u21, s[i .. i + 4], 16) catch return self.fail("bad \\u escape");
                        var buf: [4]u8 = undefined;
                        const n = std.unicode.utf8Encode(v, &buf) catch return self.fail("bad \\u escape");
                        try out.appendSlice(self.arena, buf[0..n]);
                        i += 4;
                    },
                    else => {
                        try out.append(self.arena, '\\');
                        try out.append(self.arena, e);
                    },
                }
                continue;
            }
            if (c == '\n') self.line += 1;
            try out.append(self.arena, c);
            i += 1;
        }
        p.* = i;
        return .{ .kind = .string, .text = out.items, .line = line };
    }

    fn lexNumber(self: *Lexer, p: *usize) Error!Token {
        const s = self.src;
        const line = self.line;
        const start = p.*;
        if (s[p.*] == '0' and p.* + 1 < s.len and (s[p.* + 1] == 'x' or s[p.* + 1] == 'X' or
            s[p.* + 1] == 'o' or s[p.* + 1] == 'O' or s[p.* + 1] == 'b' or s[p.* + 1] == 'B'))
        {
            const base: u8 = switch (s[p.* + 1]) {
                'x', 'X' => 16,
                'o', 'O' => 8,
                else => 2,
            };
            p.* += 2;
            const ds = p.*;
            while (p.* < s.len and (std.ascii.isAlphanumeric(s[p.*]) or s[p.*] == '_')) p.* += 1;
            const cleaned = try stripUnderscores(self.arena, s[ds..p.*]);
            const v = std.fmt.parseInt(i64, cleaned, base) catch return self.fail("bad integer literal");
            return .{ .kind = .integer, .int = v, .line = line };
        }
        var is_float = false;
        while (p.* < s.len and (std.ascii.isDigit(s[p.*]) or s[p.*] == '_')) p.* += 1;
        if (p.* + 1 < s.len and s[p.*] == '.' and std.ascii.isDigit(s[p.* + 1])) {
            is_float = true;
            p.* += 1;
            while (p.* < s.len and (std.ascii.isDigit(s[p.*]) or s[p.*] == '_')) p.* += 1;
        }
        if (p.* < s.len and (s[p.*] == 'e' or s[p.*] == 'E')) {
            var q = p.* + 1;
            if (q < s.len and (s[q] == '+' or s[q] == '-')) q += 1;
            if (q < s.len and std.ascii.isDigit(s[q])) {
                is_float = true;
                p.* = q;
                while (p.* < s.len and std.ascii.isDigit(s[p.*])) p.* += 1;
            }
        }
        const cleaned = try stripUnderscores(self.arena, s[start..p.*]);
        if (is_float) {
            const v = std.fmt.parseFloat(f64, cleaned) catch return self.fail("bad float literal");
            return .{ .kind = .float, .float = v, .line = line };
        }
        const v = std.fmt.parseInt(i64, cleaned, 10) catch return self.fail("integer literal out of range");
        return .{ .kind = .integer, .int = v, .line = line };
    }

    /// Applies `-`/`+`, `trim_blocks` and `lstrip_blocks` to the text pieces
    /// flanking every tag. `-` always wins; `+` disables the environment
    /// option for that one side.
    fn applyWhitespace(self: *Lexer) void {
        for (self.marks.items) |m| {
            if (m.before) |bi| {
                const prev = &self.pieces.items[bi];
                if (prev.chunk == .text) {
                    if (m.strip_before) {
                        prev.chunk.text = std.mem.trimEnd(u8, prev.chunk.text, " \t\r\n");
                    } else if (m.block and self.opts.lstrip_blocks and !m.plus_before) {
                        const t = prev.chunk.text;
                        var cut = t.len;
                        while (cut > 0 and (t[cut - 1] == ' ' or t[cut - 1] == '\t')) cut -= 1;
                        // Only when that run reaches the start of the line.
                        if (cut == 0 or t[cut - 1] == '\n') prev.chunk.text = t[0..cut];
                    }
                }
            }
            if (m.after < self.pieces.items.len) {
                const nxt = &self.pieces.items[m.after];
                if (nxt.chunk == .text) {
                    if (m.strip_after) {
                        nxt.chunk.text = std.mem.trimStart(u8, nxt.chunk.text, " \t\r\n");
                    } else if (m.block and self.opts.trim_blocks and !m.plus_after) {
                        const t = nxt.chunk.text;
                        if (std.mem.startsWith(u8, t, "\r\n")) {
                            nxt.chunk.text = t[2..];
                        } else if (std.mem.startsWith(u8, t, "\n")) {
                            nxt.chunk.text = t[1..];
                        }
                    }
                }
            }
        }
    }
};

fn stripUnderscores(arena: std.mem.Allocator, s: []const u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '_') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    for (s) |c| if (c != '_') try out.append(arena, c);
    return out.items;
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Index of the next `{{`, `{%` or `{#`. `{` alone, and `{` followed by
/// anything else, is ordinary text.
fn findTagStart(src: []const u8, from: usize) ?usize {
    var i = from;
    while (i + 1 < src.len) : (i += 1) {
        if (src[i] != '{') continue;
        switch (src[i + 1]) {
            '{', '%', '#' => return i,
            else => {},
        }
    }
    return null;
}
