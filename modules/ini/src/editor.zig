// SPDX-License-Identifier: MIT

//! Edit an INI file and write it back: `Editor`. The source's lines are kept as
//! they came, in a list that edits splice into, so a line nobody asked to
//! change comes out byte for byte -- comments, blank lines, indentation, the
//! spacing around separators, CRLF, a BOM, a missing final newline, and (under
//! a lenient parse) the lines that were skipped. Unedited, `write` reproduces
//! the input exactly; that is the round-trip property `fuzz_test.zig` checks.
//!
//! An edit either keeps the file meaning exactly what was asked, proved by
//! reading the new line back with the parser's own classifier, or it is
//! `error.NotRepresentable` and nothing changed. So is `error.OutOfMemory`:
//! every edit allocates and reserves all it needs first, then commits with
//! operations that cannot fail. The only trace of a failed edit is memory the
//! arena keeps until `deinit`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const Options = root.Options;
const names = @import("names.zig");
const scan = @import("scan.zig");
const wr = @import("write.zig");

pub const EditError = Allocator.Error || error{
    /// This dialect cannot say that: see `WriteError.NotRepresentable`.
    NotRepresentable,
};

const none: u32 = std.math.maxInt(u32);

const Kind = enum { blank, comment, invalid, header, entry };

const Node = struct {
    prev: u32,
    next: u32,
    /// The line(s), without the final `\n`. A continued entry is one node, its
    /// lines (and, with `empty_lines_in_values`, what lies between them) inside.
    raw: []const u8,
    /// A `\n` ends it in the source (false: the source's last line without one).
    nl: bool = true,
    /// A new line of a CRLF file: `\r` goes before its `\n`.
    cr: bool = false,
    kind: Kind,
    group: u32 = none,
    /// Entry: the previous entry of the same key in the group. Header: the
    /// previous header of the same group.
    same_prev: u32 = none,
    indent: usize = 0,
    /// Entry: `raw` goes on with a line a lenient parse skipped because it tried
    /// to continue this bare key. It stays this key's: giving the key a value
    /// would absorb it, or leave it as a new key nobody asked for.
    skipped_tail: bool = false,
    key: []const u8 = "",
    value: []const u8 = "",
    has_value: bool = true,
    /// Where the key ends and the raw value lies in `raw`.
    key_end: usize = 0,
    val_start: usize = 0,
    val_end: usize = 0,
};

const Group = struct {
    name: []const u8,
    /// The last header of this name (`none` for the entries before any header).
    header: u32,
    /// Where a new key goes: the last entry of the last instance, or its header.
    anchor: u32,
};

const NameCtx = struct {
    fold: bool,
    seed: u64,
    pub fn hash(c: NameCtx, s: []const u8) u64 {
        return names.hash(c.seed, c.fold, s);
    }
    pub fn eql(c: NameCtx, a: []const u8, b: []const u8) bool {
        return names.eql(c.fold, a, b);
    }
};

const GroupKey = struct { group: u32, key: []const u8 };

/// A new section, proved and copied, not yet in the editor. `raw` null is
/// section "", which has no header.
const NewSection = struct { name: []const u8, raw: ?[]const u8 };

/// A new entry, proved and copied, not yet in the editor.
const NewEntry = struct {
    raw: []const u8,
    key: []const u8,
    value: []const u8,
    has_value: bool,
    key_end: usize,
    val_start: usize,
    val_end: usize,
    indent: usize,
};

const KeyCtx = struct {
    fold: bool,
    seed: u64,
    pub fn hash(c: KeyCtx, k: GroupKey) u64 {
        return names.hash(c.seed +% @as(u64, k.group) *% 0x9E3779B97F4A7C15, c.fold, k.key);
    }
    pub fn eql(c: KeyCtx, a: GroupKey, b: GroupKey) bool {
        return a.group == b.group and names.eql(c.fold, a.key, b.key);
    }
};

/// Edits go to the end of an arena: the memory of a replaced value comes back
/// at `deinit`, so a long-lived editor rewriting one key forever grows.
pub const Editor = struct {
    arena: std.heap.ArenaAllocator,
    opts: Options,
    /// How a NEW line looks. `separator`: null copies the one of the last entry
    /// of the section, else `WriteOptions`'s default. `continuation_indent`
    /// and `blank_before_new_section` are read at each edit too.
    separator: ?[]const u8 = null,
    continuation_indent: []const u8 = "\t",
    blank_before_new_section: bool = true,
    /// Lines a lenient parse could not read (they stay in the text).
    skipped: []const usize = &.{},

    nodes: std.ArrayList(Node) = .empty,
    head: u32 = none,
    tail: u32 = none,
    bom: bool = false,
    /// The source's first line ended in CRLF: new lines do too.
    crlf: bool = false,
    groups: std.ArrayList(Group) = .empty,
    sec_map: std.HashMapUnmanaged([]const u8, u32, NameCtx, 80) = .empty,
    key_map: std.HashMapUnmanaged(GroupKey, u32, KeyCtx, 80) = .empty,
    seed: u64,

    /// Read `text` under `opts`. A strict parse refuses what `parse` refuses.
    pub fn init(gpa: Allocator, text: []const u8, opts: Options) (root.ParseError || Allocator.Error)!Editor {
        var info: root.ErrorInfo = .{};
        return initDiag(gpa, text, opts, &info);
    }

    pub fn initDiag(gpa: Allocator, text: []const u8, opts: Options, info: *root.ErrorInfo) (root.ParseError || Allocator.Error)!Editor {
        const info_addr: usize = @intFromPtr(info);
        var self: Editor = .{
            .arena = .init(gpa),
            .opts = opts,
            .seed = std.hash.Wyhash.hash(@intFromPtr(text.ptr) ^ (text.len *% 0x9E3779B97F4A7C15), std.mem.asBytes(&info_addr)),
        };
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        var skipped: std.ArrayList(usize) = .empty;

        const owned = try a.dupe(u8, text);
        var body: []const u8 = owned;
        if (std.mem.startsWith(u8, body, "\xEF\xBB\xBF")) {
            body = body[3..];
            self.bom = true;
        }
        if (std.mem.findScalar(u8, body, '\n')) |nl| self.crlf = nl != 0 and body[nl - 1] == '\r';

        var c: scan.Classifier = .{ .opts = opts };
        var cur_group: u32 = none;
        var cont_value: std.ArrayList(u8) = .empty;
        var pos: usize = 0;
        while (pos < body.len) {
            const nl = std.mem.findScalarPos(u8, body, pos, '\n');
            const end = nl orelse body.len;
            const line = body[pos..end];
            switch (c.feed(line)) {
                .blank => _ = try self.pushNode(.{ .prev = none, .next = none, .raw = line, .nl = nl != null, .kind = .blank }),
                .comment => _ = try self.pushNode(.{ .prev = none, .next = none, .raw = line, .nl = nl != null, .kind = .comment }),
                .invalid => |bad| {
                    if (opts.strict) {
                        info.line = bad.line;
                        return bad.err;
                    }
                    try skipped.append(a, bad.line);
                    if (bad.continues_bare_key) {
                        // Into the bare key's node, with what lay between.
                        const id = self.groups.items[cur_group].anchor;
                        const n = &self.nodes.items[id];
                        self.nodes.items.len = id + 1;
                        n.next = none;
                        self.tail = id;
                        n.raw = body[offsetIn(body, n.raw)..end];
                        n.nl = nl != null;
                        n.skipped_tail = true;
                        pos = if (nl) |x| x + 1 else body.len;
                        continue;
                    }
                    _ = try self.pushNode(.{ .prev = none, .next = none, .raw = line, .nl = nl != null, .kind = .invalid });
                },
                .section => |h| {
                    cur_group = try self.groupFor(h.name, none);
                    const id = try self.pushNode(.{ .prev = none, .next = none, .raw = line, .nl = nl != null, .kind = .header, .group = cur_group, .same_prev = self.groups.items[cur_group].header });
                    self.groups.items[cur_group].header = id;
                    self.groups.items[cur_group].anchor = id;
                },
                .entry => |e| {
                    if (cur_group == none) cur_group = try self.groupFor("", none);
                    const key_off = offsetIn(line, e.key);
                    const val_start = if (e.has_value) offsetIn(line, e.value) else line.len;
                    const id = try self.pushNode(.{
                        .prev = none,
                        .next = none,
                        .raw = line,
                        .nl = nl != null,
                        .kind = .entry,
                        .group = cur_group,
                        .indent = key_off,
                        .key = e.key,
                        .value = e.value,
                        .has_value = e.has_value,
                        .key_end = key_off + e.key.len,
                        .val_start = val_start,
                        .val_end = val_start + e.value.len,
                    });
                    self.groups.items[cur_group].anchor = id;
                    try self.linkKey(id);
                    cont_value = .empty;
                },
                .continuation => |t| {
                    // Absorb what lay between (blank lines, comments): the
                    // entry is the last entry node, and nothing but those
                    // nodes came after it.
                    const id = self.groups.items[cur_group].anchor;
                    const n = &self.nodes.items[id];
                    self.nodes.items.len = id + 1;
                    n.next = none;
                    self.tail = id;
                    if (cont_value.items.len == 0) try cont_value.appendSlice(a, n.value);
                    try cont_value.appendNTimes(a, '\n', t.blanks_before + 1);
                    try cont_value.appendSlice(a, t.text);
                    n.value = cont_value.items;
                    const start = offsetIn(body, n.raw);
                    n.raw = body[start..end];
                    n.nl = nl != null;
                    n.val_end = offsetIn(body, t.text) + t.text.len - start;
                },
            }
            pos = if (nl) |x| x + 1 else body.len;
        }
        self.skipped = skipped.items;
        return self;
    }

    pub fn deinit(self: *Editor) void {
        self.arena.deinit();
        self.* = undefined;
    }

    // ── reading ──────────────────────────────────────────────────────────────

    /// As `Document.get`, over the text as edited so far.
    pub fn get(self: *const Editor, section: []const u8, key: []const u8) ?[]const u8 {
        const g = self.group(section) orelse return null;
        if (self.lastOf(g, key)) |id| return self.nodes.items[id].value;
        if (self.opts.default_section) |ds| {
            const d = self.group(ds) orelse return null;
            if (self.lastOf(d, key)) |id| return self.nodes.items[id].value;
        }
        return null;
    }

    pub fn hasSection(self: *const Editor, section: []const u8) bool {
        return self.group(section) != null;
    }

    /// The comment lines directly above a key (null: above the section header),
    /// markers included, joined by `\n`; "" when there are none, null when the
    /// key or section is absent. Caller frees.
    pub fn getComment(self: *const Editor, gpa: Allocator, section: []const u8, key: ?[]const u8) Allocator.Error!?[]u8 {
        const at = self.commentAnchor(section, key) orelse return null;
        var first = at;
        while (self.nodes.items[first].prev != none and self.nodes.items[self.nodes.items[first].prev].kind == .comment)
            first = self.nodes.items[first].prev;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        var n = first;
        while (n != at) : (n = self.nodes.items[n].next) {
            if (out.items.len != 0) try out.append(gpa, '\n');
            try out.appendSlice(gpa, std.mem.trim(u8, self.nodes.items[n].raw, " \t\r"));
        }
        return try out.toOwnedSlice(gpa);
    }

    /// The text as edited.
    pub fn write(self: *const Editor, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.bom) try w.writeAll("\xEF\xBB\xBF");
        var id = self.head;
        while (id != none) {
            const n = &self.nodes.items[id];
            try w.writeAll(n.raw);
            if (n.nl) {
                if (n.cr) try w.writeByte('\r');
                try w.writeByte('\n');
            } else if (n.next != none) {
                // The source's last line, now followed by another. A `\r` it
                // ended in is already half of a CRLF.
                try w.writeAll(if (std.mem.endsWith(u8, n.raw, "\r")) "\n" else self.eol());
            }
            id = n.next;
        }
    }

    /// `write` into a new slice. Caller frees.
    pub fn toOwnedSlice(self: *const Editor, gpa: Allocator) Allocator.Error![]u8 {
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        self.write(&out.writer) catch return error.OutOfMemory;
        return out.toOwnedSlice();
    }

    /// The text as edited, read back into a `Document` (for `merged`, `getInt`,
    /// `interpolated`, ...). An independent copy: later edits do not reach it.
    pub fn document(self: *const Editor, gpa: Allocator) (root.ParseError || Allocator.Error)!root.Document {
        const text = try self.toOwnedSlice(gpa);
        defer gpa.free(text);
        return root.parse(gpa, text, self.opts);
    }

    // ── editing ──────────────────────────────────────────────────────────────

    /// Give `key` in `section` this value. An existing key (the last occurrence,
    /// the one `get` reads) keeps its line's indentation, separator spacing,
    /// inline comment and line ending; a continued value's replaced lines take
    /// any comment among them along. A new key goes after the last entry of the
    /// section, copying its look; a new section goes at the end of the file.
    /// `section` "" is the entries before the first header. Refused on a bare key
    /// followed by a line a lenient parse skipped for trying to continue it:
    /// `remove` the key, or mend the line.
    pub fn set(self: *Editor, section: []const u8, key: []const u8, value: []const u8) EditError!void {
        if (self.group(section)) |g| {
            if (self.lastOf(g, key)) |id| return self.replaceValue(id, value);
            const anchor = self.groups.items[g].anchor;
            const e = try self.prepareEntry(anchor, key, value, true);
            try self.reserve(1, 0, 0, 1);
            return self.commitEntry(g, e);
        }
        const h = try self.prepareSection(section);
        const e = try self.prepareEntry(none, key, value, true);
        try self.reserve(3, 1, 1, 1);
        self.commitEntry(self.commitSection(h), e);
    }

    /// Add a key without a value (`Options.no_value_keys`), or drop the value of
    /// an existing one. That takes what else was on the line and its continuation
    /// lines along: an inline comment, comments between them. The line keeps its
    /// indentation and its line ending. A key already bare stays as it is.
    pub fn setNoValue(self: *Editor, section: []const u8, key: []const u8) EditError!void {
        if (!self.opts.no_value_keys) return error.NotRepresentable;
        if (self.group(section)) |g| {
            if (self.lastOf(g, key)) |id| return self.dropValue(id);
            const anchor = self.groups.items[g].anchor;
            const e = try self.prepareEntry(anchor, key, "", false);
            try self.reserve(1, 0, 0, 1);
            return self.commitEntry(g, e);
        }
        const h = try self.prepareSection(section);
        const e = try self.prepareEntry(none, key, "", false);
        try self.reserve(3, 1, 1, 1);
        self.commitEntry(self.commitSection(h), e);
    }

    /// Remove every occurrence of `key` in `section` (a `[DEFAULT]` it inherits
    /// from is not touched), with a line skipped for trying to continue a bare
    /// one. The number removed. Allocates nothing: the error is in the signature
    /// only.
    pub fn remove(self: *Editor, section: []const u8, key: []const u8) Allocator.Error!usize {
        const g = self.group(section) orelse return 0;
        const q: GroupKey = .{ .group = g, .key = key };
        const first = self.key_map.getContext(q, self.keyCtx()) orelse return 0;
        var count: usize = 0;
        var id = first;
        while (id != none) {
            const prev_same = self.nodes.items[id].same_prev;
            self.fixAnchor(g, id);
            self.unlink(id);
            id = prev_same;
            count += 1;
        }
        _ = self.key_map.removeContext(q, self.keyCtx());
        // Section "" exists only through its entries: it has no header to stay.
        const gr = &self.groups.items[g];
        if (gr.header == none and gr.anchor == none) _ = self.sec_map.removeContext(gr.name, self.nameCtx());
        return count;
    }

    /// Add `section` at the end of the file unless it exists.
    pub fn addSection(self: *Editor, section: []const u8) EditError!void {
        if (self.group(section) != null) return;
        if (section.len == 0) {
            // It exists through its entries; nothing to add yet.
            if (!self.opts.global_entries) return error.NotRepresentable;
            return;
        }
        const h = try self.prepareSection(section);
        try self.reserve(2, 1, 1, 0);
        _ = self.commitSection(h);
    }

    /// Remove every instance of `section` with all it holds: its entries, and
    /// the comments and blank lines up to the next header. Whether it existed.
    /// Allocates nothing: the error is in the signature only.
    pub fn removeSection(self: *Editor, section: []const u8) Allocator.Error!bool {
        const g = self.group(section) orelse return false;
        const gr = &self.groups.items[g];
        if (gr.header == none) {
            // The entries before the first header; comments stay.
            var id = self.head;
            while (id != none and self.nodes.items[id].kind != .header) {
                const next = self.nodes.items[id].next;
                if (self.nodes.items[id].kind == .entry) {
                    self.dropKey(id);
                    self.unlink(id);
                }
                id = next;
            }
        }
        var h = gr.header;
        while (h != none) {
            const prev_header = self.nodes.items[h].same_prev;
            var id = self.nodes.items[h].next;
            while (id != none and self.nodes.items[id].kind != .header) {
                const next = self.nodes.items[id].next;
                if (self.nodes.items[id].kind == .entry) self.dropKey(id);
                self.unlink(id);
                id = next;
            }
            self.unlink(h);
            h = prev_header;
        }
        _ = self.sec_map.removeContext(gr.name, self.nameCtx());
        return true;
    }

    /// Replace the comment lines directly above a key (null: above the section
    /// header). `text` is lines joined by `\n`; each gets the first of
    /// `Options.comment_chars` and a space unless it starts with one. "" removes
    /// them. `error.NotRepresentable` when the key or section is absent or a
    /// line would not read as a comment.
    pub fn setComment(self: *Editor, section: []const u8, key: ?[]const u8, text: []const u8) EditError!void {
        const a = self.arena.allocator();
        const at = self.commentAnchor(section, key) orelse return error.NotRepresentable;
        var new_lines: std.ArrayList([]const u8) = .empty;
        if (text.len != 0) {
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |l| {
                // A copy either way: `text` is the caller's.
                const line = if (l.len != 0 and std.mem.findScalar(u8, self.opts.comment_chars, l[0]) != null)
                    try a.dupe(u8, l)
                else if (self.opts.comment_chars.len != 0)
                    try std.mem.concat(a, u8, &.{ self.opts.comment_chars[0..1], " ", l })
                else
                    return error.NotRepresentable;
                var c: scan.Classifier = .{ .opts = self.opts };
                switch (c.feed(line)) {
                    .comment => {},
                    else => return error.NotRepresentable,
                }
                if (line.len != 0 and line[line.len - 1] == '\r') return error.NotRepresentable;
                try new_lines.append(a, line);
            }
        }
        try self.reserve(new_lines.items.len, 0, 0, 0);
        while (self.nodes.items[at].prev != none and self.nodes.items[self.nodes.items[at].prev].kind == .comment)
            self.unlink(self.nodes.items[at].prev);
        for (new_lines.items) |line| {
            const id = self.pushDetached(.{ .prev = none, .next = none, .raw = line, .cr = self.crlf, .kind = .comment });
            self.insertBefore(id, at);
        }
        if (self.nodes.items[at].prev != none) self.guardAfter(self.nodes.items[at].prev);
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn eol(self: *const Editor) []const u8 {
        return if (self.crlf) "\r\n" else "\n";
    }

    fn nameCtx(self: *const Editor) NameCtx {
        return .{ .fold = self.opts.case_insensitive_sections, .seed = self.seed };
    }

    fn keyCtx(self: *const Editor) KeyCtx {
        return .{ .fold = self.opts.case_insensitive_keys, .seed = self.seed };
    }

    fn group(self: *const Editor, section: []const u8) ?u32 {
        return self.sec_map.getContext(section, self.nameCtx());
    }

    fn lastOf(self: *const Editor, g: u32, key: []const u8) ?u32 {
        return self.key_map.getContext(.{ .group = g, .key = key }, self.keyCtx());
    }

    fn commentAnchor(self: *const Editor, section: []const u8, key: ?[]const u8) ?u32 {
        const g = self.group(section) orelse return null;
        if (key) |k| return self.lastOf(g, k);
        const h = self.groups.items[g].header;
        return if (h == none) null else h;
    }

    /// Room for what a commit will add, so that the commit cannot fail. Reserving
    /// changes nothing anyone can see.
    fn reserve(self: *Editor, nodes: usize, groups: usize, sections: u32, new_keys: u32) Allocator.Error!void {
        const a = self.arena.allocator();
        if (self.nodes.items.len +| nodes >= none or self.groups.items.len +| groups >= none) return error.OutOfMemory;
        try self.nodes.ensureUnusedCapacity(a, nodes);
        try self.groups.ensureUnusedCapacity(a, groups);
        try self.sec_map.ensureUnusedCapacityContext(a, sections, self.nameCtx());
        try self.key_map.ensureUnusedCapacityContext(a, new_keys, self.keyCtx());
    }

    /// After `reserve`.
    fn pushDetached(self: *Editor, n: Node) u32 {
        const id: u32 = @intCast(self.nodes.items.len);
        self.nodes.appendAssumeCapacity(n);
        return id;
    }

    /// Appends at the end of the list, after `reserve`.
    fn pushAtEnd(self: *Editor, n: Node) u32 {
        const id = self.pushDetached(n);
        self.nodes.items[id].prev = self.tail;
        if (self.tail != none) self.nodes.items[self.tail].next = id else self.head = id;
        self.tail = id;
        return id;
    }

    /// For `initDiag`, whose failure discards the whole editor.
    fn pushNode(self: *Editor, n: Node) Allocator.Error!u32 {
        try self.reserve(1, 0, 0, 0);
        return self.pushAtEnd(n);
    }

    fn insertAfter(self: *Editor, id: u32, after: u32) void {
        const nodes = self.nodes.items;
        nodes[id].prev = after;
        nodes[id].next = nodes[after].next;
        if (nodes[after].next != none) nodes[nodes[after].next].prev = id else self.tail = id;
        nodes[after].next = id;
    }

    fn insertBefore(self: *Editor, id: u32, before: u32) void {
        const nodes = self.nodes.items;
        nodes[id].next = before;
        nodes[id].prev = nodes[before].prev;
        if (nodes[before].prev != none) nodes[nodes[before].prev].next = id else self.head = id;
        nodes[before].prev = id;
    }

    /// Takes the node out, keeping the classifier's view of what follows.
    fn unlink(self: *Editor, id: u32) void {
        const nodes = self.nodes.items;
        const p = nodes[id].prev;
        const q = nodes[id].next;
        if (p != none) nodes[p].next = q else self.head = q;
        if (q != none) nodes[q].prev = p else self.tail = p;
        if (p != none) self.guardAfter(p);
    }

    /// Under `continuation_lines`, a line now following an entry it did not
    /// follow before must not read as that entry's continuation (`  [b]` after
    /// `k=v`): it loses the indentation that would make it one.
    fn guardAfter(self: *Editor, start: u32) void {
        if (!self.opts.continuation_lines) return;
        const nodes = self.nodes.items;
        var from = start;
        // Each line that loses indentation may uncover the same on the next.
        while (true) {
            // Which entry a line after `from` could continue.
            var e = from;
            if (self.opts.empty_lines_in_values) {
                while (e != none and (nodes[e].kind == .blank or nodes[e].kind == .comment)) e = nodes[e].prev;
            }
            if (e == none or nodes[e].kind != .entry) return;
            var x = nodes[from].next;
            if (self.opts.empty_lines_in_values) {
                while (x != none and (nodes[x].kind == .blank or nodes[x].kind == .comment)) x = nodes[x].next;
            }
            if (x == none or nodes[x].kind == .blank or nodes[x].kind == .comment) return;
            const lead = leadingBlanks(nodes[x].raw);
            if (lead <= nodes[e].indent) return;
            const cut = lead - nodes[e].indent;
            const n = &nodes[x];
            n.raw = n.raw[cut..];
            if (n.kind == .entry) {
                n.indent -= cut;
                n.key_end -= cut;
                n.val_start -= cut;
                n.val_end -= cut;
            }
            from = x;
        }
    }

    fn fixAnchor(self: *Editor, g: u32, id: u32) void {
        const nodes = self.nodes.items;
        const gr = &self.groups.items[g];
        if (gr.anchor != id) return;
        var p = nodes[id].prev;
        while (p != none and nodes[p].kind != .entry and nodes[p].kind != .header) p = nodes[p].prev;
        // An entry or header of another group cannot come before a header of
        // this one without this one's header in between, except for group "".
        gr.anchor = if (p != none and nodes[p].group == g) p else none;
    }

    fn dropKey(self: *Editor, id: u32) void {
        const n = &self.nodes.items[id];
        _ = self.key_map.removeContext(.{ .group = n.group, .key = n.key }, self.keyCtx());
    }

    fn groupFor(self: *Editor, name: []const u8, header: u32) Allocator.Error!u32 {
        const a = self.arena.allocator();
        const ctx = self.nameCtx();
        const gop = try self.sec_map.getOrPutContext(a, name, ctx);
        if (gop.found_existing) return gop.value_ptr.*;
        errdefer _ = self.sec_map.removeContext(name, ctx);
        if (self.groups.items.len >= none) return error.OutOfMemory;
        const owned = try a.dupe(u8, name);
        gop.key_ptr.* = owned;
        const id: u32 = @intCast(self.groups.items.len);
        try self.groups.append(a, .{ .name = owned, .header = header, .anchor = header });
        gop.value_ptr.* = id;
        return id;
    }

    fn linkKey(self: *Editor, id: u32) Allocator.Error!void {
        const n = &self.nodes.items[id];
        const gop = try self.key_map.getOrPutContext(self.arena.allocator(), .{ .group = n.group, .key = n.key }, self.keyCtx());
        n.same_prev = if (gop.found_existing) gop.value_ptr.* else none;
        gop.value_ptr.* = id;
    }

    fn indentOf(self: *const Editor, anchor: u32) []const u8 {
        if (anchor == none) return "";
        const n = &self.nodes.items[anchor];
        return if (n.kind == .entry) n.raw[0..n.indent] else "";
    }

    fn separatorFor(self: *const Editor, anchor: u32, buf: *[3]u8) error{NotRepresentable}![]const u8 {
        if (self.separator) |s| return s;
        if (anchor != none) {
            const n = &self.nodes.items[anchor];
            if (n.kind == .entry and n.has_value) return n.raw[n.key_end..n.val_start];
        }
        return wr.defaultSeparator(&self.opts, buf);
    }

    /// The value replaced in place. Everything new is built first.
    fn replaceValue(self: *Editor, id: u32, value: []const u8) EditError!void {
        const a = self.arena.allocator();
        const n = self.nodes.items[id];
        if (n.skipped_tail) return error.NotRepresentable;
        var buf: [3]u8 = undefined;
        // A bare key gains a separator; else the old value's place is kept.
        const sep: []const u8 = if (n.has_value) "" else try self.separatorFor(none, &buf);
        const val_start_old = if (n.has_value) n.val_start else n.key_end;
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(a, n.raw[0..val_start_old]);
        try out.appendSlice(a, sep);
        const val_start = out.items.len;
        // Continuation lines are the entry's indentation plus the indent.
        const indent = try std.mem.concat(a, u8, &.{ n.raw[0..n.indent], self.continuation_indent });
        try wr.appendValue(a, &out, value, indent, self.eol());
        const val_end = out.items.len;
        try out.appendSlice(a, n.raw[if (n.has_value) n.val_end else n.key_end..]);
        if (!wr.verifyEntry(out.items, n.key, value, true, &self.opts)) return error.NotRepresentable;
        const owned = try a.dupe(u8, value);
        const m = &self.nodes.items[id];
        m.raw = out.items;
        m.value = owned;
        m.has_value = true;
        m.val_start = val_start;
        m.val_end = val_end;
    }

    /// `setNoValue` on an existing key.
    fn dropValue(self: *Editor, id: u32) EditError!void {
        const n = self.nodes.items[id];
        if (!n.has_value) return;
        // The line's own ending stays; in a raw text it is the last byte.
        const raw = if (std.mem.endsWith(u8, n.raw, "\r"))
            try std.mem.concat(self.arena.allocator(), u8, &.{ n.raw[0..n.key_end], "\r" })
        else
            n.raw[0..n.key_end];
        if (!wr.verifyEntry(raw, n.key, "", false, &self.opts)) return error.NotRepresentable;
        const m = &self.nodes.items[id];
        m.raw = raw;
        m.value = "";
        m.has_value = false;
        m.val_start = n.key_end;
        m.val_end = n.key_end;
    }

    /// An entry that would follow `anchor`, copying its look, proved and copied.
    fn prepareEntry(self: *Editor, anchor: u32, key: []const u8, value: []const u8, has_value: bool) EditError!NewEntry {
        const a = self.arena.allocator();
        var buf: [3]u8 = undefined;
        const indent = self.indentOf(anchor);
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(a, indent);
        try out.appendSlice(a, key);
        const key_end = out.items.len;
        var val_start = out.items.len;
        if (has_value) {
            try out.appendSlice(a, try self.separatorFor(anchor, &buf));
            val_start = out.items.len;
            const cont_indent = try std.mem.concat(a, u8, &.{ indent, self.continuation_indent });
            try wr.appendValue(a, &out, value, cont_indent, self.eol());
        }
        if (!wr.verifyEntry(out.items, key, value, has_value, &self.opts)) return error.NotRepresentable;
        return .{
            .raw = out.items,
            .key = try a.dupe(u8, key),
            .value = try a.dupe(u8, value),
            .has_value = has_value,
            .key_end = key_end,
            .val_start = val_start,
            .val_end = out.items.len,
            .indent = indent.len,
        };
    }

    /// Needs `reserve(1, 0, 0, 1)`.
    fn commitEntry(self: *Editor, g: u32, e: NewEntry) void {
        const anchor = self.groups.items[g].anchor;
        const id = self.pushDetached(.{
            .prev = none,
            .next = none,
            .raw = e.raw,
            .cr = self.crlf,
            .kind = .entry,
            .group = g,
            .indent = e.indent,
            .key = e.key,
            .value = e.value,
            .has_value = e.has_value,
            .key_end = e.key_end,
            .val_start = e.val_start,
            .val_end = e.val_end,
        });
        const gop = self.key_map.getOrPutAssumeCapacityContext(.{ .group = g, .key = e.key }, self.keyCtx());
        self.nodes.items[id].same_prev = if (gop.found_existing) gop.value_ptr.* else none;
        gop.value_ptr.* = id;
        if (anchor != none) {
            self.insertAfter(id, anchor);
        } else {
            // The entries before the first header, or none yet at all.
            var x = self.head;
            while (x != none and self.nodes.items[x].kind != .header) x = self.nodes.items[x].next;
            if (x != none) {
                self.insertBefore(id, x);
            } else if (self.tail != none) {
                self.insertAfter(id, self.tail);
            } else {
                self.head = id;
                self.tail = id;
            }
        }
        self.groups.items[g].anchor = id;
        self.guardAfter(id);
    }

    /// A section that does not exist yet, proved and copied.
    fn prepareSection(self: *Editor, section: []const u8) EditError!NewSection {
        const a = self.arena.allocator();
        if (section.len == 0) {
            if (!self.opts.global_entries) return error.NotRepresentable;
            return .{ .name = "", .raw = null };
        }
        const raw = try std.mem.concat(a, u8, &.{ "[", section, "]" });
        if (!wr.verifyHeader(raw, section, &self.opts)) return error.NotRepresentable;
        return .{ .name = raw[1 .. raw.len - 1], .raw = raw };
    }

    /// Needs `reserve(2, 1, 1, _)`. The new group's id.
    fn commitSection(self: *Editor, h: NewSection) u32 {
        const g: u32 = @intCast(self.groups.items.len);
        self.groups.appendAssumeCapacity(.{ .name = h.name, .header = none, .anchor = none });
        self.sec_map.putAssumeCapacityContext(h.name, g, self.nameCtx());
        if (h.raw) |raw| {
            if (self.blank_before_new_section and self.tail != none and self.nodes.items[self.tail].kind != .blank)
                _ = self.pushAtEnd(.{ .prev = none, .next = none, .raw = "", .cr = self.crlf, .kind = .blank });
            const id = self.pushAtEnd(.{ .prev = none, .next = none, .raw = raw, .cr = self.crlf, .kind = .header, .group = g });
            self.groups.items[g].header = id;
            self.groups.items[g].anchor = id;
        }
        return g;
    }
};

fn offsetIn(outer: []const u8, inner: []const u8) usize {
    return @intFromPtr(inner.ptr) - @intFromPtr(outer.ptr);
}

fn leadingBlanks(s: []const u8) usize {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) i += 1;
    return i;
}

test "offsets are as wide as the text: 4 GiB of blanks cannot overflow them" {
    // A runtime test would need a 4 GiB input; the field it would have
    // overflowed was a `u32` filled with `@intCast`.
    try std.testing.expectEqual(usize, @FieldType(Node, "indent"));
}
