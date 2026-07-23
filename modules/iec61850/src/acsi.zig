// SPDX-License-Identifier: MIT

//! The **IEC 61850 ACSI naming layer** on top of MMS — object references and
//! functional constraints.
//!
//! IEC 61850 names things twice and the two forms are not interchangeable:
//!
//! * the **ACSI form** a human and an SCL file use —
//!   `LDName/LNName.DOName.DAName` (`simpleIOGenericIO/GGIO1.AnIn1.mag.f`),
//!   where the functional constraint is *not* part of the string; and
//! * the **MMS form** on the wire — `LDName` as the MMS domain, and
//!   `LNName$FC$DOName$DAName` as the item id
//!   (`GGIO1$MX$AnIn1$mag$f`), with the FC **injected as the second
//!   component**.
//!
//! That injection is the whole difficulty. The FC is metadata in one form and a
//! path component in the other, so a round trip needs it carried alongside; and
//! because it sits *between* the logical node and the data object, a naive
//! `s/./$/g` produces a name the IED silently reports as non-existent.
//!
//! The functional constraints themselves partition an IED's data model:
//! measurements (`MX`) and status (`ST`) live in different MMS variables from
//! configuration (`CF`), descriptions (`DC`), control (`CO`) and the reporting,
//! logging and GOOSE control blocks (`RP`, `BR`, `LG`, `GO`, `GS`). Reading
//! `stVal` under `MX` instead of `ST` is not an error the protocol reports —
//! the object simply does not exist.

const std = @import("std");
const mms = @import("mms.zig");

pub const Error = error{
    /// No `/` separating the logical device from the logical node.
    MissingLogicalDevice,
    /// An empty logical device, logical node or path component.
    EmptyComponent,
    /// More path components than the fixed reference holds.
    TooManyComponents,
    /// A separator this form does not use (`$` in an ACSI reference, `.` in an
    /// MMS item id).
    UnexpectedSeparator,
    /// The second MMS component is not a functional constraint.
    UnknownFunctionalConstraint,
    /// The reference is longer than IEC 61850-7-2 allows.
    ReferenceTooLong,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// The MMS form needs a logical node, an FC and at least one component.
    IncompleteReference,
};

/// IEC 61850-7-2 §Table caps a `VisibleString` object reference at 129 octets
/// (`ObjRef`); the longer `VisibleString255` applies to a few attributes only.
pub const max_reference_len: usize = 129;
/// `DO` plus nested `SDO`s plus `DA` plus nested attributes. Six is deeper than
/// any standard CDC.
pub const max_components: usize = 8;

/// The functional constraints of IEC 61850-7-2 §Table 21.
pub const FunctionalConstraint = enum {
    /// Status information.
    ST,
    /// Measurands (analogue values).
    MX,
    /// Control — the `Oper`/`SBO`/`Cancel` attributes.
    CO,
    /// Setpoint.
    SP,
    /// Substitution.
    SV,
    /// Configuration.
    CF,
    /// Description.
    DC,
    /// Setting group.
    SG,
    /// Setting group editable.
    SE,
    /// Extended definition.
    EX,
    /// Buffered report control block.
    BR,
    /// Unbuffered report control block.
    RP,
    /// Log control block.
    LG,
    /// GOOSE control block.
    GO,
    /// GSSE control block.
    GS,
    /// Multicast sampled value control block.
    MS,
    /// Unicast sampled value control block.
    US,

    pub fn parse(s: []const u8) Error!FunctionalConstraint {
        if (s.len != 2) return error.UnknownFunctionalConstraint;
        inline for (@typeInfo(FunctionalConstraint).@"enum".fields) |f| {
            if (std.mem.eql(u8, s, f.name)) return @enumFromInt(f.value);
        }
        return error.UnknownFunctionalConstraint;
    }

    pub fn name(self: FunctionalConstraint) []const u8 {
        return @tagName(self);
    }

    /// Whether writing under this constraint can operate plant. `CO` is the
    /// obvious one; `SP`, `SV`, `SE` and `SG` change how the IED behaves and
    /// are nearly as consequential.
    pub fn isOperational(self: FunctionalConstraint) bool {
        return switch (self) {
            .CO, .SP, .SV, .SG, .SE => true,
            else => false,
        };
    }

    /// Control blocks live under these; everything else is data.
    pub fn isControlBlock(self: FunctionalConstraint) bool {
        return switch (self) {
            .BR, .RP, .LG, .GO, .GS, .MS, .US => true,
            else => false,
        };
    }
};

/// A parsed object reference. Everything points into the caller's string; the
/// struct owns nothing.
pub const ObjectReference = struct {
    /// Logical device — the MMS domain.
    ld: []const u8,
    /// Logical node, e.g. `GGIO1` or `LLN0`.
    ln: []const u8,
    /// Null in an ACSI reference (where the FC is carried separately).
    fc: ?FunctionalConstraint = null,
    components: [max_components][]const u8 = undefined,
    component_count: u8 = 0,

    pub fn path(self: *const ObjectReference) []const []const u8 {
        return self.components[0..self.component_count];
    }

    /// The data object (first component), or null for a bare logical node.
    pub fn dataObject(self: *const ObjectReference) ?[]const u8 {
        return if (self.component_count > 0) self.components[0] else null;
    }

    /// The last component — the data attribute a read or write actually names.
    pub fn leaf(self: *const ObjectReference) ?[]const u8 {
        return if (self.component_count > 0) self.components[self.component_count - 1] else null;
    }

    pub fn eql(a: *const ObjectReference, b: *const ObjectReference) bool {
        if (!std.mem.eql(u8, a.ld, b.ld) or !std.mem.eql(u8, a.ln, b.ln)) return false;
        if (a.fc != b.fc) return false;
        if (a.component_count != b.component_count) return false;
        for (a.path(), b.path()) |x, y| {
            if (!std.mem.eql(u8, x, y)) return false;
        }
        return true;
    }

    /// The MMS `ObjectName` this reference addresses. `item_buf` receives the
    /// `$`-separated item id and must outlive the returned name.
    pub fn objectName(self: *const ObjectReference, item_buf: []u8) Error!mms.ObjectName {
        return .{ .domain_specific = .{ .domain = self.ld, .item = try self.mmsItem(item_buf) } };
    }

    /// Writes the MMS item id: `LN$FC$C1$C2…`.
    pub fn mmsItem(self: *const ObjectReference, out: []u8) Error![]const u8 {
        var w: usize = 0;
        w += try put(out, w, self.ln);
        if (self.fc) |fc| {
            w += try put(out, w, "$");
            w += try put(out, w, fc.name());
        }
        for (self.path()) |c| {
            w += try put(out, w, "$");
            w += try put(out, w, c);
        }
        return out[0..w];
    }

    /// Writes the full MMS form: `LD/LN$FC$C1$C2…`.
    pub fn toMms(self: *const ObjectReference, out: []u8) Error![]const u8 {
        var w: usize = 0;
        w += try put(out, w, self.ld);
        w += try put(out, w, "/");
        const item = try self.mmsItem(out[w..]);
        return out[0 .. w + item.len];
    }

    /// Writes the ACSI form: `LD/LN.C1.C2…`. The functional constraint is
    /// **dropped**, because it is not part of an ACSI reference.
    pub fn toAcsi(self: *const ObjectReference, out: []u8) Error![]const u8 {
        var w: usize = 0;
        w += try put(out, w, self.ld);
        w += try put(out, w, "/");
        w += try put(out, w, self.ln);
        for (self.path()) |c| {
            w += try put(out, w, ".");
            w += try put(out, w, c);
        }
        return out[0..w];
    }
};

fn put(out: []u8, at: usize, s: []const u8) Error!usize {
    if (out.len < at + s.len) return error.BufferTooSmall;
    @memcpy(out[at..][0..s.len], s);
    return s.len;
}

/// Parses the ACSI form `LDName/LNName[.Comp]*`. The functional constraint is
/// supplied separately because an ACSI reference does not carry one.
pub fn parseAcsi(s: []const u8, fc: ?FunctionalConstraint) Error!ObjectReference {
    if (s.len == 0) return error.EmptyComponent;
    if (s.len > max_reference_len) return error.ReferenceTooLong;
    if (std.mem.indexOfScalar(u8, s, '$') != null) return error.UnexpectedSeparator;
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.MissingLogicalDevice;
    if (slash == 0 or slash + 1 >= s.len) return error.EmptyComponent;
    if (std.mem.indexOfScalarPos(u8, s, slash + 1, '/') != null) return error.UnexpectedSeparator;

    var ref = ObjectReference{ .ld = s[0..slash], .ln = undefined, .fc = fc };
    var it = std.mem.splitScalar(u8, s[slash + 1 ..], '.');
    ref.ln = it.first();
    if (ref.ln.len == 0) return error.EmptyComponent;
    while (it.next()) |c| {
        if (c.len == 0) return error.EmptyComponent;
        if (ref.component_count == max_components) return error.TooManyComponents;
        ref.components[ref.component_count] = c;
        ref.component_count += 1;
    }
    return ref;
}

/// Parses the MMS form `LDName/LNName$FC$Comp…`, i.e. the domain and item id
/// joined by `/`.
pub fn parseMms(
    s: []const u8,
) Error!ObjectReference {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.MissingLogicalDevice;
    if (slash == 0 or slash + 1 >= s.len) return error.EmptyComponent;
    return parseMmsParts(s[0..slash], s[slash + 1 ..]);
}

/// Parses a domain plus an MMS item id — the two halves of a
/// `domain-specific` `ObjectName`, which is how a reference arrives off the
/// wire.
pub fn parseMmsParts(domain: []const u8, item: []const u8) Error!ObjectReference {
    if (domain.len == 0 or item.len == 0) return error.EmptyComponent;
    if (domain.len + item.len + 1 > max_reference_len) return error.ReferenceTooLong;
    if (std.mem.indexOfScalar(u8, item, '.') != null) return error.UnexpectedSeparator;
    if (std.mem.indexOfScalar(u8, item, '/') != null) return error.UnexpectedSeparator;

    var ref = ObjectReference{ .ld = domain, .ln = undefined };
    var it = std.mem.splitScalar(u8, item, '$');
    ref.ln = it.first();
    if (ref.ln.len == 0) return error.EmptyComponent;
    const fc_str = it.next() orelse return error.IncompleteReference;
    if (fc_str.len == 0) return error.EmptyComponent;
    ref.fc = try FunctionalConstraint.parse(fc_str);
    while (it.next()) |c| {
        if (c.len == 0) return error.EmptyComponent;
        if (ref.component_count == max_components) return error.TooManyComponents;
        ref.components[ref.component_count] = c;
        ref.component_count += 1;
    }
    return ref;
}

/// Convenience: ACSI reference + FC straight to the MMS `ObjectName` a read or
/// write needs. `item_buf` must outlive the returned name.
pub fn objectNameFor(reference: []const u8, fc: FunctionalConstraint, item_buf: []u8) Error!mms.ObjectName {
    const ref = try parseAcsi(reference, fc);
    return ref.objectName(item_buf);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the ACSI and MMS forms of a captured reference convert both ways" {
    // The measurement a real client read.
    const acsi = "simpleIOGenericIO/GGIO1.AnIn1.mag.f";
    const ref = try parseAcsi(acsi, .MX);
    try testing.expectEqualStrings("simpleIOGenericIO", ref.ld);
    try testing.expectEqualStrings("GGIO1", ref.ln);
    try testing.expectEqual(FunctionalConstraint.MX, ref.fc.?);
    try testing.expectEqual(@as(usize, 3), ref.path().len);
    try testing.expectEqualStrings("AnIn1", ref.dataObject().?);
    try testing.expectEqualStrings("f", ref.leaf().?);

    var buf: [128]u8 = undefined;
    // The MMS item id is exactly what the captured request carried.
    try testing.expectEqualStrings("GGIO1$MX$AnIn1$mag$f", try ref.mmsItem(&buf));
    var buf2: [128]u8 = undefined;
    try testing.expectEqualStrings("simpleIOGenericIO/GGIO1$MX$AnIn1$mag$f", try ref.toMms(&buf2));
    var buf3: [128]u8 = undefined;
    try testing.expectEqualStrings(acsi, try ref.toAcsi(&buf3));

    // And the round trip back from the MMS form reconstructs the same thing.
    const back = try parseMms("simpleIOGenericIO/GGIO1$MX$AnIn1$mag$f");
    try testing.expect(ref.eql(&back));
}

test "the object name a read request needs comes straight out of the reference" {
    var buf: [128]u8 = undefined;
    const name = try objectNameFor("simpleIOGenericIO/GGIO1.NamPlt.vendor", .DC, &buf);
    try testing.expectEqualStrings("simpleIOGenericIO", name.domain_specific.domain);
    try testing.expectEqualStrings("GGIO1$DC$NamPlt$vendor", name.domain_specific.item);
}

test "a report control block reference has no data object below it" {
    // The URCB the captured client read and then wrote to.
    const ref = try parseMms("simpleIOGenericIO/LLN0$RP$EventsRCB01");
    try testing.expectEqualStrings("LLN0", ref.ln);
    try testing.expectEqual(FunctionalConstraint.RP, ref.fc.?);
    try testing.expect(ref.fc.?.isControlBlock());
    try testing.expectEqualStrings("EventsRCB01", ref.leaf().?);
    try testing.expectEqual(@as(usize, 1), ref.path().len);

    // And one of its attributes.
    const attr = try parseMms("simpleIOGenericIO/LLN0$RP$EventsRCB01$TrgOps");
    try testing.expectEqual(@as(usize, 2), attr.path().len);
    try testing.expectEqualStrings("TrgOps", attr.leaf().?);
}

test "a GOOSE control block reference parses" {
    const ref = try parseMms("simpleIOGenericIO/LLN0$GO$gcbAnalogValues");
    try testing.expectEqual(FunctionalConstraint.GO, ref.fc.?);
    try testing.expect(ref.fc.?.isControlBlock());
    // The dataset reference has no FC at all — it is a plain named variable
    // list, which is why it must be parsed as parts rather than as an MMS item.
    try testing.expectError(
        error.UnknownFunctionalConstraint,
        parseMms("simpleIOGenericIO/LLN0$AnalogValues"),
    );
}

test "every functional constraint parses and names itself" {
    inline for (@typeInfo(FunctionalConstraint).@"enum".fields) |f| {
        const fc = try FunctionalConstraint.parse(f.name);
        try testing.expectEqualStrings(f.name, fc.name());
    }
    try testing.expectEqual(@as(usize, 17), @typeInfo(FunctionalConstraint).@"enum".fields.len);
    try testing.expect(FunctionalConstraint.CO.isOperational());
    try testing.expect(FunctionalConstraint.SP.isOperational());
    try testing.expect(!FunctionalConstraint.MX.isOperational());
    try testing.expect(!FunctionalConstraint.ST.isOperational());
}

test "an unknown functional constraint is refused, not passed through" {
    try testing.expectError(error.UnknownFunctionalConstraint, FunctionalConstraint.parse("XX"));
    try testing.expectError(error.UnknownFunctionalConstraint, FunctionalConstraint.parse("M"));
    try testing.expectError(error.UnknownFunctionalConstraint, FunctionalConstraint.parse("MXX"));
    try testing.expectError(error.UnknownFunctionalConstraint, FunctionalConstraint.parse("mx"));
    try testing.expectError(error.UnknownFunctionalConstraint, parseMms("LD/LN$ZZ$DO"));
}

test "malformed ACSI references are typed errors" {
    try testing.expectError(error.EmptyComponent, parseAcsi("", .ST));
    try testing.expectError(error.MissingLogicalDevice, parseAcsi("GGIO1.AnIn1", .ST));
    try testing.expectError(error.EmptyComponent, parseAcsi("/GGIO1.AnIn1", .ST));
    try testing.expectError(error.EmptyComponent, parseAcsi("LD/", .ST));
    // A trailing or doubled dot leaves an empty component.
    try testing.expectError(error.EmptyComponent, parseAcsi("LD/GGIO1.", .ST));
    try testing.expectError(error.EmptyComponent, parseAcsi("LD/GGIO1..mag", .ST));
    // The MMS separator has no business in an ACSI reference.
    try testing.expectError(error.UnexpectedSeparator, parseAcsi("LD/GGIO1$ST$Ind1", .ST));
    // Two logical devices.
    try testing.expectError(error.UnexpectedSeparator, parseAcsi("LD/GGIO1/X", .ST));
    // Too deep.
    try testing.expectError(
        error.TooManyComponents,
        parseAcsi("LD/LN.a.b.c.d.e.f.g.h.i", .ST),
    );
    // Too long.
    const long = "LD/" ++ "A" ** 200;
    try testing.expectError(error.ReferenceTooLong, parseAcsi(long, .ST));
}

test "malformed MMS references are typed errors" {
    try testing.expectError(error.MissingLogicalDevice, parseMms("GGIO1$ST$Ind1"));
    try testing.expectError(error.EmptyComponent, parseMms("/GGIO1$ST$Ind1"));
    try testing.expectError(error.EmptyComponent, parseMms("LD/"));
    // The ACSI separator has no business in an MMS item id.
    try testing.expectError(error.UnexpectedSeparator, parseMms("LD/GGIO1$ST$Ind1.stVal"));
    // A bare logical node with no FC.
    try testing.expectError(error.IncompleteReference, parseMms("LD/GGIO1"));
    // Empty components either side of the FC.
    try testing.expectError(error.EmptyComponent, parseMms("LD/$ST$Ind1"));
    try testing.expectError(error.EmptyComponent, parseMms("LD/GGIO1$$Ind1"));
    try testing.expectError(error.EmptyComponent, parseMms("LD/GGIO1$ST$"));
    try testing.expectError(error.EmptyComponent, parseMmsParts("", "GGIO1$ST$Ind1"));
    try testing.expectError(error.EmptyComponent, parseMmsParts("LD", ""));
    try testing.expectError(
        error.TooManyComponents,
        parseMms("LD/LN$ST$a$b$c$d$e$f$g$h$i"),
    );
}

test "a too-small output buffer is refused rather than truncating a reference" {
    const ref = try parseAcsi("simpleIOGenericIO/GGIO1.AnIn1.mag.f", .MX);
    var small: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, ref.mmsItem(&small));
    try testing.expectError(error.BufferTooSmall, ref.toMms(&small));
    try testing.expectError(error.BufferTooSmall, ref.toAcsi(&small));
}

test "the FC changes the wire name, and nothing else does" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const st = try (try parseAcsi("LD/GGIO1.Ind1.stVal", .ST)).mmsItem(&a);
    const mx = try (try parseAcsi("LD/GGIO1.Ind1.stVal", .MX)).mmsItem(&b);
    try testing.expectEqualStrings("GGIO1$ST$Ind1$stVal", st);
    try testing.expectEqualStrings("GGIO1$MX$Ind1$stVal", mx);
    try testing.expect(!std.mem.eql(u8, st, mx));
}

test "a reference with no components below the logical node round trips" {
    const ref = try parseAcsi("LD/LLN0", null);
    try testing.expectEqual(@as(usize, 0), ref.path().len);
    try testing.expect(ref.dataObject() == null);
    try testing.expect(ref.leaf() == null);
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("LLN0", try ref.mmsItem(&buf));
}

test "fuzz: reference parsing never panics" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, 200);
    const s = buf[0..len];
    if (parseAcsi(s, .ST)) |ref| {
        var out: [512]u8 = undefined;
        // Anything that parsed must re-serialise and re-parse to the same thing.
        const acsi = try ref.toAcsi(&out);
        var out2: [512]u8 = undefined;
        const again = try parseAcsi(acsi, .ST);
        _ = try again.toAcsi(&out2);
        try testing.expect(ref.eql(&again));
    } else |_| {}
    if (parseMms(s)) |ref| {
        var out: [512]u8 = undefined;
        const wire = try ref.toMms(&out);
        const again = try parseMms(wire);
        try testing.expect(ref.eql(&again));
    } else |_| {}
}
