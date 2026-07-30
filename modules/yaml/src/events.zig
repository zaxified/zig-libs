// SPDX-License-Identifier: MIT
//! The yaml-test-suite event serialization — stage 3's *text* form.
//!
//! This is not a pretty-printer: it is the exact line format the
//! `yaml-test-suite` `test.event` files are written in, so a parse can be
//! diffed byte-for-byte against 402 third-party expectations. Reproduced here
//! because that oracle is the module's whole verification story.
//!
//! Grammar (one event per line, `\n`-terminated):
//!
//! ```text
//! +STR / -STR
//! +DOC              (explicit start prints `+DOC ---`)
//! -DOC              (explicit end   prints `-DOC ...`)
//! +MAP [{}] [&anchor] [<tag>]      `{}` marks flow style
//! +SEQ [[]] [&anchor] [<tag>]      `[]` marks flow style
//! -MAP / -SEQ
//! =VAL [&anchor] [<tag>] <style><content>
//! =ALI *anchor
//! ```
//!
//! `<style>` is one of `:` plain, `'` single-quoted, `"` double-quoted,
//! `|` literal, `>` folded. Content is escaped for `\`, LF, TAB, CR and
//! BS only; every other byte — including all non-ASCII — is emitted raw.
//! The field order (flow marker, then anchor, then tag) was read off the
//! suite files, not assumed.

const std = @import("std");
const parser = @import("parser.zig");

const Event = parser.Event;

pub fn styleChar(s: parser.ScalarStyle) u8 {
    return switch (s) {
        .plain => ':',
        .single_quoted => '\'',
        .double_quoted => '"',
        .literal => '|',
        .folded => '>',
    };
}

pub fn writeEscaped(w: *std.Io.Writer, text: []const u8) !void {
    for (text) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        '\r' => try w.writeAll("\\r"),
        0x08 => try w.writeAll("\\b"),
        else => try w.writeByte(c),
    };
}

pub fn writeEvent(w: *std.Io.Writer, ev: Event) !void {
    switch (ev) {
        .stream_start => try w.writeAll("+STR"),
        .stream_end => try w.writeAll("-STR"),
        .document_start => |d| try w.writeAll(if (d.explicit) "+DOC ---" else "+DOC"),
        .document_end => |d| try w.writeAll(if (d.explicit) "-DOC ..." else "-DOC"),
        .mapping_start => |c| {
            try w.writeAll("+MAP");
            if (c.style == .flow) try w.writeAll(" {}");
            try writeProps(w, c.anchor, c.tag);
        },
        .mapping_end => try w.writeAll("-MAP"),
        .sequence_start => |c| {
            try w.writeAll("+SEQ");
            if (c.style == .flow) try w.writeAll(" []");
            try writeProps(w, c.anchor, c.tag);
        },
        .sequence_end => try w.writeAll("-SEQ"),
        .alias => |a| {
            try w.writeAll("=ALI *");
            try w.writeAll(a.anchor);
        },
        .scalar => |s| {
            try w.writeAll("=VAL");
            try writeProps(w, s.anchor, s.tag);
            try w.writeByte(' ');
            try w.writeByte(styleChar(s.style));
            try writeEscaped(w, s.value);
        },
    }
    try w.writeByte('\n');
}

fn writeProps(w: *std.Io.Writer, anchor: ?[]const u8, tag: ?[]const u8) !void {
    if (anchor) |a| {
        try w.writeAll(" &");
        try w.writeAll(a);
    }
    if (tag) |t| {
        try w.writeAll(" <");
        try w.writeAll(t);
        try w.writeAll(">");
    }
}
