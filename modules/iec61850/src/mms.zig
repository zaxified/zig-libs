// SPDX-License-Identifier: MIT

//! **MMS** (ISO 9506, Manufacturing Message Specification) as profiled by
//! IEC 61850-8-1 — the PDUs and the services an IEC 61850 client and server
//! actually exchange.
//!
//! ```text
//! MMSpdu ::= CHOICE {
//!   confirmed-RequestPDU  [0], confirmed-ResponsePDU [1], confirmed-ErrorPDU [2],
//!   unconfirmed-PDU       [3], rejectPDU             [4],
//!   cancel-RequestPDU     [5], cancel-ResponsePDU    [6], cancel-ErrorPDU    [7],
//!   initiate-RequestPDU   [8], initiate-ResponsePDU  [9], initiate-ErrorPDU  [10],
//!   conclude-RequestPDU  [11], conclude-ResponsePDU [12], conclude-ErrorPDU  [13] }
//! ```
//!
//! Things worth knowing before reading the code:
//!
//! * **The invoke id is the only correlation there is.** MMS allows several
//!   outstanding confirmed requests (`Initiate` negotiates how many), and a
//!   response carries nothing but the id to say which request it answers.
//!   Matching on arrival order instead works right up until an IED answers out
//!   of order, which they do.
//! * **`AccessResult` overlaps `Data` deliberately.** `failure [0] IMPLICIT
//!   DataAccessError` and the `Data` alternatives `[1]..[17]` share the same
//!   context namespace, which is legal exactly because `Data` has no `[0]`. A
//!   decoder that assumes every access result is a value silently reports
//!   whatever `DataAccessError` happens to look like.
//! * **`Read-Request` and `Write-Request` order their fields differently.** A
//!   read is `{ specificationWithResult [0], variableAccessSpecification [1] }`;
//!   a write is `{ variableAccessSpecification, listOfData [0] }` — where the
//!   access specification's own `listOfVariable` is *also* `[0]`. Two `[0]`
//!   fields in a row, told apart by position.
//! * **`InformationReport` is unconfirmed and unsolicited.** It is how every
//!   IEC 61850 report arrives, and its variable-access-specification is
//!   normally the VMD-specific name `"RPT"` rather than anything the client
//!   asked for.

const std = @import("std");
const ber = @import("ber.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = mmsdata.Error || error{
    /// A top-level MMSpdu tag this module does not model.
    UnknownPdu,
    /// A confirmed-service tag this module does not model.
    UnsupportedService,
    /// A required field is absent.
    MissingField,
    /// The peer answered a different invoke id than was asked.
    InvokeIdMismatch,
    /// The peer rejected the request at the MMS layer.
    ServiceError,
    /// The peer sent a `rejectPDU`.
    Rejected,
};

pub const Data = mmsdata.Data;

// ── PDU tags ────────────────────────────────────────────────────────────────

pub const PduKind = enum(u32) {
    confirmed_request = 0,
    confirmed_response = 1,
    confirmed_error = 2,
    unconfirmed = 3,
    reject = 4,
    cancel_request = 5,
    cancel_response = 6,
    cancel_error = 7,
    initiate_request = 8,
    initiate_response = 9,
    initiate_error = 10,
    conclude_request = 11,
    conclude_response = 12,
    conclude_error = 13,
    _,

    pub fn tag(self: PduKind) ber.Tag {
        return ber.Tag.ctxc(@intFromEnum(self));
    }
};

/// `ConfirmedServiceRequest` / `ConfirmedServiceResponse` alternatives. Only
/// the ones IEC 61850-8-1 profiles are named; the rest decode as an unknown
/// number rather than wedging the parser.
pub const Service = enum(u32) {
    status = 0,
    get_name_list = 1,
    identify = 2,
    rename = 3,
    read = 4,
    write = 5,
    get_variable_access_attributes = 6,
    define_named_variable = 7,
    delete_variable_access = 10,
    define_named_variable_list = 11,
    get_named_variable_list_attributes = 12,
    delete_named_variable_list = 13,
    read_journal = 65,
    file_open = 72,
    file_read = 73,
    file_close = 74,
    file_rename = 75,
    file_delete = 76,
    file_directory = 77,
    _,

    pub fn tag(self: Service) ber.Tag {
        return ber.Tag.ctxc(@intFromEnum(self));
    }
};

/// `UnconfirmedService` alternatives.
pub const UnconfirmedService = enum(u32) {
    information_report = 0,
    unsolicited_status = 1,
    event_notification = 2,
    _,
};

/// `ObjectClass.basicObjectClass`, the scope selector for `GetNameList`.
pub const ObjectClass = enum(u8) {
    named_variable = 0,
    scattered_access = 1,
    named_variable_list = 2,
    named_type = 3,
    semaphore = 4,
    event_condition = 5,
    event_action = 6,
    event_enrollment = 7,
    journal = 8,
    domain = 9,
    program_invocation = 10,
    operator_station = 11,
    data_exchange = 12,
    access_control_list = 13,
    _,
};

/// `DataAccessError` — the per-variable failure code inside an `AccessResult`.
pub const DataAccessError = enum(u8) {
    object_invalidated = 0,
    hardware_fault = 1,
    temporarily_unavailable = 2,
    object_access_denied = 3,
    object_undefined = 4,
    invalid_address = 5,
    type_unsupported = 6,
    type_inconsistent = 7,
    object_attribute_inconsistent = 8,
    object_access_unsupported = 9,
    object_non_existent = 10,
    object_value_invalid = 11,
    _,
};

/// `ServiceError.errorClass` — the whole-request failure in a
/// `confirmed-ErrorPDU`.
pub const ErrorClass = enum(u32) {
    vmd_state = 0,
    application_reference = 1,
    definition = 2,
    resource = 3,
    service = 4,
    service_preempt = 5,
    time_resolution = 6,
    access = 7,
    initiate = 8,
    conclude = 9,
    cancel = 10,
    file = 11,
    others = 12,
    _,
};

// ── object names ────────────────────────────────────────────────────────────

/// `ObjectName ::= CHOICE { vmd-specific [0], domain-specific [1], aa-specific [2] }`.
///
/// IEC 61850 maps a logical device to the domain and everything below it to the
/// item id, so `domain_specific{"simpleIOGenericIO", "GGIO1$MX$AnIn1$mag$f"}`
/// is one data attribute.
pub const ObjectName = union(enum) {
    vmd_specific: []const u8,
    domain_specific: struct { domain: []const u8, item: []const u8 },
    aa_specific: []const u8,

    pub fn encode(self: ObjectName, w: *ber.Writer) Error!void {
        switch (self) {
            .vmd_specific => |s| try w.primitive(ber.Tag.ctx(0), s),
            .domain_specific => |d| {
                const m = w.mark();
                try w.primitive(ber.Tag.uni(ber.Universal.visible_string), d.item);
                try w.primitive(ber.Tag.uni(ber.Universal.visible_string), d.domain);
                try w.header(ber.Tag.ctxc(1), m);
            },
            .aa_specific => |s| try w.primitive(ber.Tag.ctx(2), s),
        }
    }

    pub fn decode(bytes: []const u8) Error!ObjectName {
        const e = try ber.decode(bytes);
        if (e.tag.class != .context) return error.UnexpectedTag;
        return switch (e.tag.number) {
            0 => .{ .vmd_specific = e.content },
            1 => blk: {
                var it = ber.Iterator.init(e.content);
                const domain = try it.expect(ber.Tag.uni(ber.Universal.visible_string));
                const item = try it.expect(ber.Tag.uni(ber.Universal.visible_string));
                break :blk .{ .domain_specific = .{ .domain = domain.content, .item = item.content } };
            },
            2 => .{ .aa_specific = e.content },
            else => error.UnexpectedTag,
        };
    }

    pub fn eql(a: ObjectName, b: ObjectName) bool {
        return switch (a) {
            .vmd_specific => |x| b == .vmd_specific and std.mem.eql(u8, x, b.vmd_specific),
            .aa_specific => |x| b == .aa_specific and std.mem.eql(u8, x, b.aa_specific),
            .domain_specific => |x| b == .domain_specific and
                std.mem.eql(u8, x.domain, b.domain_specific.domain) and
                std.mem.eql(u8, x.item, b.domain_specific.item),
        };
    }
};

/// One entry of a `listOfVariable`: a named variable and, optionally, an
/// **alternate access** — the `[5]` sub-specification that addresses an array
/// element or a structure component rather than the whole variable. It is kept
/// as raw octets: the sub-syntax is large, rarely used outside array access,
/// and preserving it verbatim is what lets a captured request round-trip
/// byte-for-byte instead of being silently widened to the whole object.
pub const VariableEntry = struct {
    name: ObjectName,
    alternate_access: ?[]const u8 = null,
};

/// `VariableAccessSpecification ::= CHOICE { listOfVariable [0], variableListName [1] }`.
pub const AccessSpec = union(enum) {
    /// One or more named variables, read or written together.
    variables: []const ObjectName,
    /// The same, with alternate-access sub-specifications preserved.
    entries: []const VariableEntry,
    /// A previously defined named variable list — how every IEC 61850 dataset
    /// and report control block is addressed.
    variable_list: ObjectName,

    pub fn encode(self: AccessSpec, w: *ber.Writer) Error!void {
        switch (self) {
            .variables => |names| {
                const list = w.mark();
                var i: usize = names.len;
                while (i > 0) {
                    i -= 1;
                    const entry = w.mark();
                    const spec = w.mark();
                    try names[i].encode(w);
                    try w.header(ber.Tag.ctxc(0), spec); // variableSpecification.name [0]
                    try w.header(ber.Tag.sequence, entry);
                }
                try w.header(ber.Tag.ctxc(0), list);
            },
            .entries => |list_entries| {
                const list = w.mark();
                var i: usize = list_entries.len;
                while (i > 0) {
                    i -= 1;
                    const entry = w.mark();
                    if (list_entries[i].alternate_access) |aa| try w.bytes(aa);
                    const spec = w.mark();
                    try list_entries[i].name.encode(w);
                    try w.header(ber.Tag.ctxc(0), spec);
                    try w.header(ber.Tag.sequence, entry);
                }
                try w.header(ber.Tag.ctxc(0), list);
            },
            .variable_list => |n| {
                const m = w.mark();
                try n.encode(w);
                try w.header(ber.Tag.ctxc(1), m);
            },
        }
    }
};

/// Walks a decoded `listOfVariable`.
pub const VariableIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *VariableIterator) Error!?ObjectName {
        const e = (try self.nextEntry()) orelse return null;
        return e.name;
    }

    /// The same, keeping any alternate-access sub-specification.
    pub fn nextEntry(self: *VariableIterator) Error!?VariableEntry {
        const e = (try self.inner.next()) orelse return null;
        if (!e.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
        var f = ber.Iterator.init(e.content);
        const spec = try f.expect(ber.Tag.ctxc(0)); // variableSpecification.name
        var entry = VariableEntry{ .name = try ObjectName.decode(spec.content) };
        while (try f.next()) |m| {
            // alternateAccess [5], kept verbatim.
            if (m.tag.eqlLoose(ber.Tag.ctxc(5))) entry.alternate_access = m.raw;
        }
        return entry;
    }
};

/// A decoded `VariableAccessSpecification`.
pub const DecodedAccessSpec = union(enum) {
    variables: VariableIterator,
    variable_list: ObjectName,

    pub fn decode(bytes: []const u8) Error!DecodedAccessSpec {
        const e = try ber.decode(bytes);
        if (e.tag.eql(ber.Tag.ctxc(0))) return .{ .variables = .{ .inner = ber.Iterator.init(e.content) } };
        if (e.tag.eql(ber.Tag.ctxc(1))) return .{ .variable_list = try ObjectName.decode(e.content) };
        return error.UnexpectedTag;
    }
};

// ── top-level PDU ───────────────────────────────────────────────────────────

pub const ConfirmedRequest = struct {
    invoke_id: u32,
    service: Service,
    /// The service-specific content, i.e. inside the service tag.
    body: []const u8,
};

pub const ConfirmedResponse = ConfirmedRequest;

pub const ConfirmedErrorPdu = struct {
    invoke_id: u32,
    error_class: ErrorClass,
    /// The class-specific code.
    code: i32,
};

pub const UnconfirmedPdu = struct {
    service: UnconfirmedService,
    body: []const u8,
};

pub const RejectPdu = struct {
    /// Null when the reject could not be attributed to a request.
    invoke_id: ?u32,
    reject_reason_class: u32,
    reject_code: i32,
};

pub const Pdu = union(enum) {
    confirmed_request: ConfirmedRequest,
    confirmed_response: ConfirmedResponse,
    confirmed_error: ConfirmedErrorPdu,
    unconfirmed: UnconfirmedPdu,
    reject: RejectPdu,
    initiate_request: Initiate,
    initiate_response: Initiate,
    initiate_error: ConfirmedErrorPdu,
    conclude_request: void,
    conclude_response: void,
    conclude_error: ConfirmedErrorPdu,
    cancel_request: u32,
    cancel_response: u32,
};

pub fn decode(bytes: []const u8) Error!Pdu {
    const e = try ber.decode(bytes);
    if (e.tag.class != .context) return error.UnknownPdu;
    const kind: PduKind = @enumFromInt(e.tag.number);
    return switch (kind) {
        .confirmed_request => .{ .confirmed_request = try decodeConfirmed(e.content) },
        .confirmed_response => .{ .confirmed_response = try decodeConfirmed(e.content) },
        .confirmed_error => .{ .confirmed_error = try decodeConfirmedError(e.content) },
        .initiate_error => .{ .initiate_error = try decodeConfirmedError(e.content) },
        .conclude_error => .{ .conclude_error = try decodeConfirmedError(e.content) },
        .unconfirmed => blk: {
            const inner = try ber.decode(e.content);
            if (inner.tag.class != .context) return error.UnknownPdu;
            break :blk .{ .unconfirmed = .{
                .service = @enumFromInt(inner.tag.number),
                .body = inner.content,
            } };
        },
        .reject => .{ .reject = try decodeReject(e.content) },
        .initiate_request => .{ .initiate_request = try Initiate.decode(e.content) },
        .initiate_response => .{ .initiate_response = try Initiate.decode(e.content) },
        .conclude_request => .{ .conclude_request = {} },
        .conclude_response => .{ .conclude_response = {} },
        .cancel_request => .{ .cancel_request = try ber.decodeUint(u32, e.content) },
        .cancel_response => .{ .cancel_response = try ber.decodeUint(u32, e.content) },
        else => error.UnknownPdu,
    };
}

fn decodeConfirmed(content: []const u8) Error!ConfirmedRequest {
    var it = ber.Iterator.init(content);
    const id = try it.expect(ber.Tag.uni(ber.Universal.integer));
    const invoke_id = try ber.decodeUint(u32, id.content);
    const svc = (try it.next()) orelse return error.MissingField;
    if (svc.tag.class != .context) return error.UnsupportedService;
    return .{
        .invoke_id = invoke_id,
        .service = @enumFromInt(svc.tag.number),
        .body = svc.content,
    };
}

fn decodeConfirmedError(content: []const u8) Error!ConfirmedErrorPdu {
    var it = ber.Iterator.init(content);
    var invoke_id: u32 = 0;
    var error_class: ErrorClass = .others;
    var code: i32 = 0;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            invoke_id = try ber.decodeUint(u32, e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(2))) {
            // serviceError [2] IMPLICIT ServiceError
            var s = ber.Iterator.init(e.content);
            while (try s.next()) |f| {
                if (f.tag.eql(ber.Tag.ctxc(0))) {
                    // errorClass [0] CHOICE — the alternative *is* the class.
                    const c = try ber.decode(f.content);
                    error_class = @enumFromInt(c.tag.number);
                    code = ber.decodeInt(i32, c.content) catch 0;
                }
            }
        }
    }
    return .{ .invoke_id = invoke_id, .error_class = error_class, .code = code };
}

fn decodeReject(content: []const u8) Error!RejectPdu {
    var it = ber.Iterator.init(content);
    var r = RejectPdu{ .invoke_id = null, .reject_reason_class = 0, .reject_code = 0 };
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            r.invoke_id = try ber.decodeUint(u32, e.content);
        } else if (e.tag.class == .context and e.tag.number >= 1) {
            r.reject_reason_class = e.tag.number;
            r.reject_code = ber.decodeInt(i32, e.content) catch 0;
        }
    }
    return r;
}

// ── Initiate / Conclude ─────────────────────────────────────────────────────

/// The `Initiate` request and response share a shape; the tags inside
/// `initRequestDetail`/`initResponseDetail` are the same.
pub const Initiate = struct {
    local_detail: ?i32 = null,
    max_serv_outstanding_calling: i16 = 5,
    max_serv_outstanding_called: i16 = 5,
    data_structure_nesting_level: ?i8 = null,
    version_number: i16 = 1,
    /// `proposedParameterCBB` — which MMS parameter options are supported.
    parameter_cbb: ?ber.BitString = null,
    /// `servicesSupported` — a bit per confirmed service.
    services_supported: ?ber.BitString = null,

    /// Bit positions inside `servicesSupported` for the services this module
    /// implements. IEC 61850-8-1 requires a server to advertise these.
    pub const service_bit = struct {
        pub const status: usize = 0;
        pub const get_name_list: usize = 1;
        pub const identify: usize = 2;
        pub const read: usize = 4;
        pub const write: usize = 5;
        pub const get_variable_access_attributes: usize = 6;
        pub const define_named_variable_list: usize = 11;
        pub const get_named_variable_list_attributes: usize = 12;
        pub const delete_named_variable_list: usize = 13;
        pub const information_report: usize = 79;
        pub const file_open: usize = 72;
        pub const file_read: usize = 73;
        pub const file_close: usize = 74;
        pub const file_directory: usize = 77;
    };

    pub fn supports(self: Initiate, bit: usize) bool {
        const s = self.services_supported orelse return false;
        return s.bit(bit);
    }

    pub fn decode(content: []const u8) Error!Initiate {
        var r = Initiate{};
        var it = ber.Iterator.init(content);
        while (try it.next()) |e| {
            if (e.tag.class != .context) continue;
            switch (e.tag.number) {
                0 => r.local_detail = try ber.decodeInt(i32, e.content),
                1 => r.max_serv_outstanding_calling = try ber.decodeInt(i16, e.content),
                2 => r.max_serv_outstanding_called = try ber.decodeInt(i16, e.content),
                3 => r.data_structure_nesting_level = try ber.decodeInt(i8, e.content),
                4 => {
                    var d = ber.Iterator.init(e.content);
                    while (try d.next()) |f| {
                        if (f.tag.class != .context) continue;
                        switch (f.tag.number) {
                            0 => r.version_number = try ber.decodeInt(i16, f.content),
                            1 => r.parameter_cbb = try ber.BitString.parse(f.content),
                            2 => r.services_supported = try ber.BitString.parse(f.content),
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }
        return r;
    }

    /// Encodes as an `initiate-RequestPDU` (`request = true`) or an
    /// `initiate-ResponsePDU`.
    pub fn encode(self: Initiate, request: bool, out: []u8) Error![]const u8 {
        var w = ber.Writer.init(out);
        const outer = w.mark();
        const detail = w.mark();
        if (self.services_supported) |s| try w.bitStringRaw(ber.Tag.ctx(2), s.unused, s.bytes);
        if (self.parameter_cbb) |p| try w.bitStringRaw(ber.Tag.ctx(1), p.unused, p.bytes);
        try w.integer(ber.Tag.ctx(0), self.version_number);
        try w.header(ber.Tag.ctxc(4), detail);
        if (self.data_structure_nesting_level) |n| try w.integer(ber.Tag.ctx(3), n);
        try w.integer(ber.Tag.ctx(2), self.max_serv_outstanding_called);
        try w.integer(ber.Tag.ctx(1), self.max_serv_outstanding_calling);
        if (self.local_detail) |d| try w.integer(ber.Tag.ctx(0), d);
        try w.header((if (request) PduKind.initiate_request else PduKind.initiate_response).tag(), outer);
        return w.done();
    }
};

pub fn encodeConcludeRequest(out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.header(PduKind.conclude_request.tag(), m);
    return w.done();
}

pub fn encodeConcludeResponse(out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.header(PduKind.conclude_response.tag(), m);
    return w.done();
}

// ── confirmed request / response frames ─────────────────────────────────────

/// Opens a `confirmed-RequestPDU`: the caller writes the service body first
/// (the writer is backwards), then calls this to close it.
pub fn closeConfirmedRequest(w: *ber.Writer, mark: usize, service: Service, invoke_id: u32) Error!void {
    try w.header(service.tag(), mark);
    try w.unsigned(ber.Tag.uni(ber.Universal.integer), invoke_id);
    try w.header(PduKind.confirmed_request.tag(), mark);
}

pub fn closeConfirmedResponse(w: *ber.Writer, mark: usize, service: Service, invoke_id: u32) Error!void {
    try w.header(service.tag(), mark);
    try w.unsigned(ber.Tag.uni(ber.Universal.integer), invoke_id);
    try w.header(PduKind.confirmed_response.tag(), mark);
}

/// A `confirmed-ErrorPDU`. `code` is the class-specific error number.
pub fn encodeConfirmedError(invoke_id: u32, class: ErrorClass, code: i32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    const se = w.mark();
    const ec = w.mark();
    try w.integer(ber.Tag.ctx(@intFromEnum(class)), code);
    try w.header(ber.Tag.ctxc(0), ec);
    try w.header(ber.Tag.ctxc(2), se);
    try w.unsigned(ber.Tag.ctx(0), invoke_id);
    try w.header(PduKind.confirmed_error.tag(), outer);
    return w.done();
}

// ── Read ────────────────────────────────────────────────────────────────────

/// `Read-Request ::= SEQUENCE { specificationWithResult [0] IMPLICIT BOOLEAN
/// DEFAULT FALSE, variableAccessSpecification [1] }`.
pub fn encodeRead(invoke_id: u32, spec: AccessSpec, with_result: bool, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    const vas = w.mark();
    try spec.encode(&w);
    try w.header(ber.Tag.ctxc(1), vas);
    // DEFAULT FALSE: omitted when false, exactly as the reference stack does.
    if (with_result) try w.boolean(ber.Tag.ctx(0), true);
    try closeConfirmedRequest(&w, m, .read, invoke_id);
    return w.done();
}

pub const ReadRequest = struct {
    with_result: bool,
    spec: DecodedAccessSpec,
};

pub fn decodeReadRequest(body: []const u8) Error!ReadRequest {
    var it = ber.Iterator.init(body);
    var with_result = false;
    var spec: ?DecodedAccessSpec = null;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            with_result = try ber.decodeBool(e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(1))) {
            spec = try DecodedAccessSpec.decode(e.content);
        }
    }
    return .{ .with_result = with_result, .spec = spec orelse return error.MissingField };
}

/// `AccessResult ::= CHOICE { failure [0] IMPLICIT DataAccessError, success Data }`.
pub const AccessResult = union(enum) {
    failure: DataAccessError,
    success: Data,

    pub fn decode(bytes: []const u8) Error!AccessResult {
        const e = try ber.decode(bytes);
        if (e.tag.eql(ber.Tag.ctx(0))) {
            return .{ .failure = @enumFromInt(try ber.decodeUint(u8, e.content)) };
        }
        return .{ .success = try Data.decode(bytes) };
    }
};

/// Walks a `listOfAccessResult`.
pub const AccessResultIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *AccessResultIterator) Error!?AccessResult {
        const e = (try self.inner.next()) orelse return null;
        if (e.tag.eql(ber.Tag.ctx(0))) {
            return .{ .failure = @enumFromInt(try ber.decodeUint(u8, e.content)) };
        }
        const kind = try mmsdata.Kind.fromTag(e.tag);
        if (kind.isConstructed() != e.tag.constructed) return error.WrongDataType;
        return .{ .success = .{ .kind = kind, .content = e.content, .raw = e.raw } };
    }
};

pub const ReadResponse = struct {
    /// Echoed only when the request set `specificationWithResult`.
    spec: ?DecodedAccessSpec,
    results: AccessResultIterator,
};

pub fn decodeReadResponse(body: []const u8) Error!ReadResponse {
    var it = ber.Iterator.init(body);
    var spec: ?DecodedAccessSpec = null;
    var results: ?AccessResultIterator = null;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctxc(0))) {
            spec = try DecodedAccessSpec.decode(e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(1))) {
            results = .{ .inner = ber.Iterator.init(e.content) };
        }
    }
    return .{ .spec = spec, .results = results orelse return error.MissingField };
}

/// Closes a `Read-Response` around already written access results.
pub fn closeReadResponse(w: *ber.Writer, results_mark: usize, invoke_id: u32) Error!void {
    try w.header(ber.Tag.ctxc(1), results_mark);
    try closeConfirmedResponse(w, results_mark, .read, invoke_id);
}

/// Writes one failed `AccessResult`.
pub fn emitAccessFailure(w: *ber.Writer, e: DataAccessError) Error!void {
    try w.integer(ber.Tag.ctx(0), @intFromEnum(e));
}

// ── Write ───────────────────────────────────────────────────────────────────

/// `Write-Request ::= SEQUENCE { variableAccessSpecification, listOfData [0] }`.
/// `values` are complete, already encoded `Data` TLVs.
pub fn encodeWrite(invoke_id: u32, spec: AccessSpec, values: []const []const u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    const data = w.mark();
    var i: usize = values.len;
    while (i > 0) {
        i -= 1;
        try w.bytes(values[i]);
    }
    try w.header(ber.Tag.ctxc(0), data);
    try spec.encode(&w);
    try closeConfirmedRequest(&w, m, .write, invoke_id);
    return w.done();
}

pub const WriteRequest = struct {
    spec: DecodedAccessSpec,
    /// The `listOfData` body — walk with `mmsdata` through a `ber.Iterator`.
    values: []const u8,
};

pub fn decodeWriteRequest(body: []const u8) Error!WriteRequest {
    var it = ber.Iterator.init(body);
    var spec: ?DecodedAccessSpec = null;
    var values: ?[]const u8 = null;
    var index: usize = 0;
    while (try it.next()) |e| : (index += 1) {
        // Both fields can be [0]: the access specification's `listOfVariable`
        // and `listOfData`. Position decides.
        if (index == 0) {
            spec = try DecodedAccessSpec.decode(body[0..e.total_len]);
        } else if (e.tag.eql(ber.Tag.ctxc(0))) {
            values = e.content;
        }
    }
    return .{
        .spec = spec orelse return error.MissingField,
        .values = values orelse return error.MissingField,
    };
}

/// `Write-Response ::= SEQUENCE OF CHOICE { failure [0], success [1] IMPLICIT NULL }`.
pub const WriteResult = union(enum) { failure: DataAccessError, success };

pub const WriteResultIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *WriteResultIterator) Error!?WriteResult {
        const e = (try self.inner.next()) orelse return null;
        if (e.tag.eql(ber.Tag.ctx(0))) return .{ .failure = @enumFromInt(try ber.decodeUint(u8, e.content)) };
        if (e.tag.eqlLoose(ber.Tag.ctx(1))) return .success;
        return error.UnexpectedTag;
    }
};

pub fn decodeWriteResponse(body: []const u8) WriteResultIterator {
    return .{ .inner = ber.Iterator.init(body) };
}

pub fn encodeWriteResponse(invoke_id: u32, results: []const WriteResult, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    var i: usize = results.len;
    while (i > 0) {
        i -= 1;
        switch (results[i]) {
            .failure => |e| try w.integer(ber.Tag.ctx(0), @intFromEnum(e)),
            .success => try w.null_(ber.Tag.ctx(1)),
        }
    }
    try closeConfirmedResponse(&w, m, .write, invoke_id);
    return w.done();
}

// ── GetNameList ─────────────────────────────────────────────────────────────

pub const Scope = union(enum) {
    vmd,
    domain: []const u8,
    aa,
};

pub fn encodeGetNameList(
    invoke_id: u32,
    class: ObjectClass,
    scope: Scope,
    continue_after: ?[]const u8,
    out: []u8,
) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    if (continue_after) |c| try w.primitive(ber.Tag.ctx(2), c);
    const s = w.mark();
    switch (scope) {
        .vmd => try w.null_(ber.Tag.ctx(0)),
        .domain => |d| try w.primitive(ber.Tag.ctx(1), d),
        .aa => try w.null_(ber.Tag.ctx(2)),
    }
    try w.header(ber.Tag.ctxc(1), s);
    const c = w.mark();
    try w.integer(ber.Tag.ctx(0), @intFromEnum(class));
    try w.header(ber.Tag.ctxc(0), c);
    try closeConfirmedRequest(&w, m, .get_name_list, invoke_id);
    return w.done();
}

pub const GetNameListRequest = struct {
    class: ObjectClass,
    scope: Scope,
    continue_after: ?[]const u8,
};

pub fn decodeGetNameListRequest(body: []const u8) Error!GetNameListRequest {
    var it = ber.Iterator.init(body);
    var class: ObjectClass = .named_variable;
    var scope: Scope = .vmd;
    var continue_after: ?[]const u8 = null;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctxc(0))) {
            const c = try ber.expect(e.content, ber.Tag.ctx(0));
            class = @enumFromInt(try ber.decodeUint(u8, c.content));
        } else if (e.tag.eql(ber.Tag.ctxc(1))) {
            const s = try ber.decode(e.content);
            scope = switch (s.tag.number) {
                0 => .vmd,
                1 => .{ .domain = s.content },
                2 => .aa,
                else => return error.UnexpectedTag,
            };
        } else if (e.tag.eql(ber.Tag.ctx(2))) {
            continue_after = e.content;
        }
    }
    return .{ .class = class, .scope = scope, .continue_after = continue_after };
}

pub const IdentifierIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *IdentifierIterator) Error!?[]const u8 {
        const e = (try self.inner.next()) orelse return null;
        if (!e.tag.eqlLoose(ber.Tag.uni(ber.Universal.visible_string))) return error.UnexpectedTag;
        return e.content;
    }
};

pub const GetNameListResponse = struct {
    names: IdentifierIterator,
    /// `moreFollows` DEFAULT TRUE — an omitted field means *more follow*, which
    /// is the opposite of what a zero-initialised struct would say.
    more_follows: bool,
};

pub fn decodeGetNameListResponse(body: []const u8) Error!GetNameListResponse {
    var it = ber.Iterator.init(body);
    var names: ?IdentifierIterator = null;
    var more = true;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctxc(0))) {
            names = .{ .inner = ber.Iterator.init(e.content) };
        } else if (e.tag.eql(ber.Tag.ctx(1))) {
            more = try ber.decodeBool(e.content);
        }
    }
    return .{ .names = names orelse return error.MissingField, .more_follows = more };
}

pub fn encodeGetNameListResponse(invoke_id: u32, names: []const []const u8, more: bool, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.boolean(ber.Tag.ctx(1), more);
    const list = w.mark();
    var i: usize = names.len;
    while (i > 0) {
        i -= 1;
        try w.primitive(ber.Tag.uni(ber.Universal.visible_string), names[i]);
    }
    try w.header(ber.Tag.ctxc(0), list);
    try closeConfirmedResponse(&w, m, .get_name_list, invoke_id);
    return w.done();
}

// ── Identify ────────────────────────────────────────────────────────────────

pub fn encodeIdentify(invoke_id: u32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try closeConfirmedRequest(&w, m, .identify, invoke_id);
    return w.done();
}

pub const IdentifyResponse = struct {
    vendor: []const u8 = &.{},
    model: []const u8 = &.{},
    revision: []const u8 = &.{},
};

pub fn decodeIdentifyResponse(body: []const u8) Error!IdentifyResponse {
    var r = IdentifyResponse{};
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class != .context) continue;
        switch (e.tag.number) {
            0 => r.vendor = e.content,
            1 => r.model = e.content,
            2 => r.revision = e.content,
            else => {},
        }
    }
    return r;
}

pub fn encodeIdentifyResponse(invoke_id: u32, r: IdentifyResponse, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.primitive(ber.Tag.ctx(2), r.revision);
    try w.primitive(ber.Tag.ctx(1), r.model);
    try w.primitive(ber.Tag.ctx(0), r.vendor);
    try closeConfirmedResponse(&w, m, .identify, invoke_id);
    return w.done();
}

// ── GetVariableAccessAttributes ─────────────────────────────────────────────

pub fn encodeGetVariableAccessAttributes(invoke_id: u32, name: ObjectName, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    const n = w.mark();
    try name.encode(&w);
    try w.header(ber.Tag.ctxc(0), n); // name [0]
    try closeConfirmedRequest(&w, m, .get_variable_access_attributes, invoke_id);
    return w.done();
}

/// A node of a decoded `TypeSpecification`. Structures and arrays are walked
/// with `components`, under the same depth bound as `Data`.
pub const TypeSpec = struct {
    /// The `TypeSpecification` alternative number; for the leaf types this is
    /// the same number as the matching `Data` alternative.
    kind: u32,
    content: []const u8,

    pub fn decode(bytes: []const u8) Error!TypeSpec {
        const e = try ber.decode(bytes);
        if (e.tag.class != .context) return error.UnexpectedTag;
        return .{ .kind = e.tag.number, .content = e.content };
    }

    pub fn isStructure(self: TypeSpec) bool {
        return self.kind == 2;
    }
    pub fn isArray(self: TypeSpec) bool {
        return self.kind == 1;
    }

    /// Members of a `structure`: `{ componentName [0] OPTIONAL, componentType [1] }`.
    pub fn components(self: TypeSpec) Error!ComponentIterator {
        if (!self.isStructure()) return error.WrongDataType;
        var it = ber.Iterator.init(self.content);
        while (try it.next()) |e| {
            if (e.tag.eql(ber.Tag.ctxc(1))) return .{ .inner = ber.Iterator.init(e.content), .depth = mmsdata.max_depth };
        }
        return error.MissingField;
    }

    /// Walks a whole type tree, checking the depth bound.
    pub fn validate(self: TypeSpec) Error!void {
        try self.validateDepth(mmsdata.max_depth);
    }

    fn validateDepth(self: TypeSpec, budget: u8) Error!void {
        if (budget == 0) return error.TooDeep;
        if (self.isStructure()) {
            var it = try self.components();
            while (try it.next()) |c| try c.type_spec.validateDepth(budget - 1);
        } else if (self.isArray()) {
            var it = ber.Iterator.initDepth(self.content, budget);
            while (try it.next()) |e| {
                if (e.tag.eql(ber.Tag.ctxc(2))) {
                    try (try TypeSpec.decode(e.content)).validateDepth(budget - 1);
                }
            }
        }
    }
};

pub const Component = struct {
    name: ?[]const u8,
    type_spec: TypeSpec,
};

pub const ComponentIterator = struct {
    inner: ber.Iterator,
    depth: u8,

    pub fn next(self: *ComponentIterator) Error!?Component {
        const e = (try self.inner.next()) orelse return null;
        if (!e.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
        var f = ber.Iterator.init(e.content);
        var name: ?[]const u8 = null;
        var ts: ?TypeSpec = null;
        while (try f.next()) |m| {
            if (m.tag.eql(ber.Tag.ctx(0))) {
                name = m.content;
            } else if (m.tag.eql(ber.Tag.ctxc(1))) {
                ts = try TypeSpec.decode(m.content);
            }
        }
        return .{ .name = name, .type_spec = ts orelse return error.MissingField };
    }
};

pub const VariableAccessAttributes = struct {
    deletable: bool,
    type_spec: TypeSpec,
};

pub fn decodeGetVariableAccessAttributesResponse(body: []const u8) Error!VariableAccessAttributes {
    var it = ber.Iterator.init(body);
    var deletable = false;
    var ts: ?TypeSpec = null;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            deletable = try ber.decodeBool(e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(2))) {
            ts = try TypeSpec.decode(e.content);
        }
    }
    return .{ .deletable = deletable, .type_spec = ts orelse return error.MissingField };
}

// ── named variable lists ────────────────────────────────────────────────────

pub fn encodeGetNamedVariableListAttributes(invoke_id: u32, name: ObjectName, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try name.encode(&w);
    try closeConfirmedRequest(&w, m, .get_named_variable_list_attributes, invoke_id);
    return w.done();
}

pub const NamedVariableListAttributes = struct {
    deletable: bool,
    variables: VariableIterator,
};

pub fn decodeGetNamedVariableListAttributesResponse(body: []const u8) Error!NamedVariableListAttributes {
    var it = ber.Iterator.init(body);
    var deletable = false;
    var vars: ?VariableIterator = null;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            deletable = try ber.decodeBool(e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(1))) {
            vars = .{ .inner = ber.Iterator.init(e.content) };
        }
    }
    return .{ .deletable = deletable, .variables = vars orelse return error.MissingField };
}

pub fn encodeDefineNamedVariableList(
    invoke_id: u32,
    name: ObjectName,
    members: []const ObjectName,
    out: []u8,
) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    const list = w.mark();
    var i: usize = members.len;
    while (i > 0) {
        i -= 1;
        const entry = w.mark();
        const spec = w.mark();
        try members[i].encode(&w);
        try w.header(ber.Tag.ctxc(0), spec);
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(ber.Tag.sequence, list);
    try name.encode(&w);
    try closeConfirmedRequest(&w, m, .define_named_variable_list, invoke_id);
    return w.done();
}

/// `scopeOfDelete`: specific(0), aa-specific(1), domain(2), vmd(3).
pub fn encodeDeleteNamedVariableList(invoke_id: u32, names: []const ObjectName, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    const list = w.mark();
    var i: usize = names.len;
    while (i > 0) {
        i -= 1;
        try names[i].encode(&w);
    }
    try w.header(ber.Tag.ctxc(1), list);
    try w.integer(ber.Tag.ctx(0), 0); // scopeOfDelete = specific
    try closeConfirmedRequest(&w, m, .delete_named_variable_list, invoke_id);
    return w.done();
}

pub const DeleteResult = struct {
    /// How many the server actually dropped; 0 with a non-zero request means
    /// nothing was deleted.
    number_deleted: u32,
    number_matched: u32,
};

pub fn decodeDeleteNamedVariableListResponse(body: []const u8) Error!DeleteResult {
    var it = ber.Iterator.init(body);
    var r = DeleteResult{ .number_deleted = 0, .number_matched = 0 };
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            r.number_matched = try ber.decodeUint(u32, e.content);
        } else if (e.tag.eql(ber.Tag.ctx(1))) {
            r.number_deleted = try ber.decodeUint(u32, e.content);
        }
    }
    return r;
}

// ── InformationReport ───────────────────────────────────────────────────────

pub const InformationReport = struct {
    spec: DecodedAccessSpec,
    /// The `listOfAccessResult` body.
    results: AccessResultIterator,
};

pub fn decodeInformationReport(body: []const u8) Error!InformationReport {
    var it = ber.Iterator.init(body);
    var spec: ?DecodedAccessSpec = null;
    var results: ?AccessResultIterator = null;
    var index: usize = 0;
    while (try it.next()) |e| : (index += 1) {
        if (index == 0) {
            spec = try DecodedAccessSpec.decode(body[0..e.total_len]);
        } else if (e.tag.eql(ber.Tag.ctxc(0))) {
            results = .{ .inner = ber.Iterator.init(e.content) };
        }
    }
    return .{
        .spec = spec orelse return error.MissingField,
        .results = results orelse return error.MissingField,
    };
}

/// Closes an `InformationReport` around already written access results.
pub fn closeInformationReport(w: *ber.Writer, results_mark: usize, spec: AccessSpec) Error!void {
    try w.header(ber.Tag.ctxc(0), results_mark);
    try spec.encode(w);
    try w.header(ber.Tag.ctxc(0), results_mark); // informationReport [0]
    try w.header(PduKind.unconfirmed.tag(), results_mark);
}

// ── file services ───────────────────────────────────────────────────────────

/// `FileName ::= SEQUENCE OF GraphicString`. IEC 61850 uses a single component.
pub fn encodeFileOpen(invoke_id: u32, path: []const u8, initial_position: u32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.unsigned(ber.Tag.ctx(1), initial_position);
    const fname = w.mark();
    try w.primitive(ber.Tag.uni(ber.Universal.graphic_string), path);
    try w.header(ber.Tag.ctxc(0), fname);
    try closeConfirmedRequest(&w, m, .file_open, invoke_id);
    return w.done();
}

pub const FileOpenResponse = struct {
    frsm_id: i32,
    size: u32 = 0,
};

pub fn decodeFileOpenResponse(body: []const u8) Error!FileOpenResponse {
    var it = ber.Iterator.init(body);
    var r = FileOpenResponse{ .frsm_id = 0 };
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            r.frsm_id = try ber.decodeInt(i32, e.content);
        } else if (e.tag.eql(ber.Tag.ctxc(1))) {
            var f = ber.Iterator.init(e.content);
            while (try f.next()) |g| {
                if (g.tag.eql(ber.Tag.ctx(0))) r.size = try ber.decodeUint(u32, g.content);
            }
        }
    }
    return r;
}

/// `FileRead-Request ::= Integer32` — the frsmID, bare, with no SEQUENCE.
pub fn encodeFileRead(invoke_id: u32, frsm_id: i32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    var tmp: [8]u8 = undefined;
    try w.bytes(tmp[0..try ber.encodeIntContent(frsm_id, &tmp)]);
    try closeConfirmedRequestPrimitive(&w, m, .file_read, invoke_id);
    return w.done();
}

pub const FileReadResponse = struct {
    data: []const u8,
    /// DEFAULT TRUE.
    more_follows: bool,
};

pub fn decodeFileReadResponse(body: []const u8) Error!FileReadResponse {
    var it = ber.Iterator.init(body);
    var data: []const u8 = &.{};
    var more = true;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctx(0))) {
            data = e.content;
        } else if (e.tag.eql(ber.Tag.ctx(1))) {
            more = try ber.decodeBool(e.content);
        }
    }
    return .{ .data = data, .more_follows = more };
}

pub fn encodeFileClose(invoke_id: u32, frsm_id: i32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    var tmp: [8]u8 = undefined;
    try w.bytes(tmp[0..try ber.encodeIntContent(frsm_id, &tmp)]);
    try closeConfirmedRequestPrimitive(&w, m, .file_close, invoke_id);
    return w.done();
}

/// `FileDirectory-Request ::= SEQUENCE { fileSpecification [0] OPTIONAL,
/// continueAfter [1] OPTIONAL }`. Both omitted lists the root, which is what
/// the captured client sent — and which produced the `bf 4d 00` long-form tag
/// with an empty body.
pub fn encodeFileDirectory(invoke_id: u32, path: ?[]const u8, continue_after: ?[]const u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    if (continue_after) |c| {
        const f = w.mark();
        try w.primitive(ber.Tag.uni(ber.Universal.graphic_string), c);
        try w.header(ber.Tag.ctxc(1), f);
    }
    if (path) |p| {
        const f = w.mark();
        try w.primitive(ber.Tag.uni(ber.Universal.graphic_string), p);
        try w.header(ber.Tag.ctxc(0), f);
    }
    try closeConfirmedRequest(&w, m, .file_directory, invoke_id);
    return w.done();
}

pub const DirectoryEntry = struct {
    name: []const u8,
    size: u32,
};

pub const DirectoryIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *DirectoryIterator) Error!?DirectoryEntry {
        const e = (try self.inner.next()) orelse return null;
        if (!e.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
        var f = ber.Iterator.init(e.content);
        var name: []const u8 = &.{};
        var size: u32 = 0;
        while (try f.next()) |g| {
            if (g.tag.eql(ber.Tag.ctxc(0))) {
                const n = try ber.decode(g.content);
                name = n.content;
            } else if (g.tag.eql(ber.Tag.ctxc(1))) {
                var a = ber.Iterator.init(g.content);
                while (try a.next()) |h| {
                    if (h.tag.eql(ber.Tag.ctx(0))) size = try ber.decodeUint(u32, h.content);
                }
            }
        }
        return .{ .name = name, .size = size };
    }
};

pub const FileDirectoryResponse = struct {
    entries: DirectoryIterator,
    more_follows: bool,
};

pub fn decodeFileDirectoryResponse(body: []const u8) Error!FileDirectoryResponse {
    var it = ber.Iterator.init(body);
    var entries: ?DirectoryIterator = null;
    var more = false;
    while (try it.next()) |e| {
        if (e.tag.eql(ber.Tag.ctxc(0))) {
            entries = .{ .inner = ber.Iterator.init(e.content) };
        } else if (e.tag.eql(ber.Tag.ctx(1))) {
            more = try ber.decodeBool(e.content);
        }
    }
    return .{ .entries = entries orelse return error.MissingField, .more_follows = more };
}

// A `[N] IMPLICIT Integer32` service body is primitive, not constructed.
fn closeConfirmedRequestPrimitive(w: *ber.Writer, mark: usize, service: Service, invoke_id: u32) Error!void {
    try w.header(ber.Tag.ctx(@intFromEnum(service)), mark);
    try w.unsigned(ber.Tag.uni(ber.Universal.integer), invoke_id);
    try w.header(PduKind.confirmed_request.tag(), mark);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const test_domain = "simpleIOGenericIO";

test "the captured Read request is rebuilt octet for octet" {
    // Captured: read of GGIO1$MX$AnIn1$mag$f in domain simpleIOGenericIO.
    const captured = [_]u8{
        0xA0, 0x38, 0x02, 0x01, 0x01, 0xA4, 0x33, 0xA1, 0x31, 0xA0, 0x2F, 0x30, 0x2D, 0xA0, 0x2B, 0xA1, 0x29,
        0x1A, 0x11,
    } ++ test_domain.* ++ [_]u8{ 0x1A, 0x14 } ++ "GGIO1$MX$AnIn1$mag$f".*;
    var out: [256]u8 = undefined;
    const names = [_]ObjectName{.{ .domain_specific = .{ .domain = test_domain, .item = "GGIO1$MX$AnIn1$mag$f" } }};
    const built = try encodeRead(1, .{ .variables = &names }, false, &out);
    try testing.expectEqualSlices(u8, &captured, built);
}

test "the captured Read response decodes to the measured value" {
    const captured = [_]u8{ 0xA1, 0x0E, 0x02, 0x01, 0x01, 0xA4, 0x09, 0xA1, 0x07, 0x87, 0x05, 0x08, 0x3D, 0x2A, 0x51, 0x55 };
    const pdu = try decode(&captured);
    const resp = pdu.confirmed_response;
    try testing.expectEqual(@as(u32, 1), resp.invoke_id);
    try testing.expectEqual(Service.read, resp.service);
    var r = try decodeReadResponse(resp.body);
    try testing.expect(r.spec == null);
    const first = (try r.results.next()).?;
    try testing.expectApproxEqAbs(@as(f64, 0.0415809), try first.success.asFloat(), 1e-6);
    try testing.expect((try r.results.next()) == null);
}

test "the captured Write request is rebuilt octet for octet" {
    const item = "GGIO1$DC$NamPlt$vendor";
    const value = "libiec61850.com";
    const captured = [_]u8{
        0xA0, 0x4B, 0x02, 0x01, 0x02, 0xA5, 0x46, 0xA0, 0x31, 0x30, 0x2F, 0xA0, 0x2D, 0xA1, 0x2B,
        0x1A, 0x11,
    } ++ test_domain.* ++ [_]u8{ 0x1A, 0x16 } ++ item.* ++ [_]u8{ 0xA0, 0x11, 0x8A, 0x0F } ++ value.*;
    var out: [256]u8 = undefined;
    var vbuf: [64]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.visibleString(&vw, value);
    const names = [_]ObjectName{.{ .domain_specific = .{ .domain = test_domain, .item = item } }};
    const vals = [_][]const u8{vw.done()};
    const built = try encodeWrite(2, .{ .variables = &names }, &vals, &out);
    try testing.expectEqualSlices(u8, &captured, built);
}

test "the captured Write response decodes as one success" {
    const captured = [_]u8{ 0xA1, 0x07, 0x02, 0x01, 0x02, 0xA5, 0x02, 0x81, 0x00 };
    const pdu = try decode(&captured);
    var it = decodeWriteResponse(pdu.confirmed_response.body);
    try testing.expectEqual(WriteResult.success, (try it.next()).?);
    try testing.expect((try it.next()) == null);
    // And the encoder rebuilds it.
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try encodeWriteResponse(2, &[_]WriteResult{.success}, &out));
}

test "the captured GetNameList exchange round trips" {
    // Request: domains, VMD scope.
    const req = [_]u8{ 0xA0, 0x0E, 0x02, 0x01, 0x01, 0xA1, 0x09, 0xA0, 0x03, 0x80, 0x01, 0x09, 0xA1, 0x02, 0x80, 0x00 };
    var out: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &req, try encodeGetNameList(1, .domain, .vmd, null, &out));
    const parsed = try decodeGetNameListRequest((try decode(&req)).confirmed_request.body);
    try testing.expectEqual(ObjectClass.domain, parsed.class);
    try testing.expect(parsed.scope == .vmd);

    // Response: one domain, moreFollows FALSE.
    const resp = [_]u8{ 0xA1, 0x1D, 0x02, 0x01, 0x01, 0xA1, 0x18, 0xA0, 0x13, 0x1A, 0x11 } ++ test_domain.* ++ [_]u8{ 0x81, 0x01, 0x00 };
    const pdu = try decode(&resp);
    var r = try decodeGetNameListResponse(pdu.confirmed_response.body);
    try testing.expect(!r.more_follows);
    try testing.expectEqualStrings(test_domain, (try r.names.next()).?);
    try testing.expect((try r.names.next()) == null);
}

test "a GetNameList with a domain scope and a continuation point" {
    var out: [128]u8 = undefined;
    const built = try encodeGetNameList(2, .named_variable, .{ .domain = test_domain }, "GGIO1$ST", &out);
    const parsed = try decodeGetNameListRequest((try decode(built)).confirmed_request.body);
    try testing.expectEqual(ObjectClass.named_variable, parsed.class);
    try testing.expectEqualStrings(test_domain, parsed.scope.domain);
    try testing.expectEqualStrings("GGIO1$ST", parsed.continue_after.?);
}

test "moreFollows defaults to TRUE when the server omits it" {
    // A response with no moreFollows field at all.
    const resp = [_]u8{ 0xA1, 0x0A, 0x02, 0x01, 0x01, 0xA1, 0x05, 0xA0, 0x03, 0x1A, 0x01, 'a' };
    const pdu = try decode(&resp);
    const r = try decodeGetNameListResponse(pdu.confirmed_response.body);
    try testing.expect(r.more_follows);
}

test "the captured named-variable-list read decodes to four booleans" {
    // Read of `LLN0$Events` with specificationWithResult TRUE, and its reply.
    const req = [_]u8{
        0xA0, 0x2E, 0x02, 0x01, 0x03, 0xA4, 0x29, 0x80, 0x01, 0x01, 0xA1, 0x24, 0xA1, 0x22, 0xA1, 0x20,
        0x1A, 0x11,
    } ++ test_domain.* ++ [_]u8{ 0x1A, 0x0B } ++ "LLN0$Events".*;
    var out: [128]u8 = undefined;
    const built = try encodeRead(
        3,
        .{ .variable_list = .{ .domain_specific = .{ .domain = test_domain, .item = "LLN0$Events" } } },
        true,
        &out,
    );
    try testing.expectEqualSlices(u8, &req, built);

    const rr = try decodeReadRequest((try decode(&req)).confirmed_request.body);
    try testing.expect(rr.with_result);
    try testing.expect(rr.spec.variable_list.domain_specific.item.len == 11);

    const resp = [_]u8{
        0xA1, 0x39, 0x02, 0x01, 0x03, 0xA4, 0x34, 0xA0, 0x24, 0xA1, 0x22, 0xA1, 0x20, 0x1A, 0x11,
    } ++ test_domain.* ++ [_]u8{ 0x1A, 0x0B } ++ "LLN0$Events".* ++
        [_]u8{ 0xA1, 0x0C, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00 };
    const pdu = try decode(&resp);
    var r = try decodeReadResponse(pdu.confirmed_response.body);
    try testing.expect(r.spec != null);
    var n: usize = 0;
    while (try r.results.next()) |ar| : (n += 1) {
        try testing.expectEqual(false, try ar.success.boolean());
    }
    try testing.expectEqual(@as(usize, 4), n);
}

test "an AccessResult failure is not mistaken for a value" {
    // `a4 05 a1 03 80 01 0a` — read reply whose only result is
    // object-non-existent(10).
    const resp = [_]u8{ 0xA1, 0x0A, 0x02, 0x01, 0x0E, 0xA4, 0x05, 0xA1, 0x03, 0x80, 0x01, 0x0A };
    const pdu = try decode(&resp);
    var r = try decodeReadResponse(pdu.confirmed_response.body);
    const first = (try r.results.next()).?;
    try testing.expectEqual(DataAccessError.object_non_existent, first.failure);
}

test "the captured Initiate request round trips field by field" {
    const captured = [_]u8{
        0xA8, 0x26,
        0x80, 0x03, 0x00, 0xFD, 0xE8, // localDetailCalling = 65000
        0x81, 0x01, 0x05, 0x82, 0x01,
        0x05, 0x83, 0x01, 0x0A, 0xA4,
        0x16, 0x80, 0x01, 0x01, 0x81,
        0x03, 0x05, 0xF1, 0x00, 0x82,
        0x0C, 0x03, 0xEE, 0x1C, 0x00,
        0x00, 0x04, 0x08, 0x00, 0x00,
        0x79, 0xEF, 0x18,
    };
    const pdu = try decode(&captured);
    const init = pdu.initiate_request;
    try testing.expectEqual(@as(i32, 65000), init.local_detail.?);
    try testing.expectEqual(@as(i16, 5), init.max_serv_outstanding_calling);
    try testing.expectEqual(@as(i16, 5), init.max_serv_outstanding_called);
    try testing.expectEqual(@as(i8, 10), init.data_structure_nesting_level.?);
    try testing.expectEqual(@as(i16, 1), init.version_number);
    // A real client advertises read, write and getNameList.
    try testing.expect(init.supports(Initiate.service_bit.get_name_list));
    try testing.expect(init.supports(Initiate.service_bit.read));
    try testing.expect(init.supports(Initiate.service_bit.write));
    try testing.expect(init.supports(Initiate.service_bit.get_variable_access_attributes));

    var out: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try init.encode(true, &out));
}

test "the captured Initiate response round trips" {
    const captured = [_]u8{
        0xA9, 0x26,
        0x80, 0x03,
        0x00, 0xFD,
        0xE8, 0x81,
        0x01, 0x05,
        0x82, 0x01,
        0x05, 0x83,
        0x01, 0x0A,
        0xA4, 0x16,
        0x80, 0x01,
        0x01, 0x81,
        0x03, 0x05,
        0xF1, 0x00,
        0x82, 0x0C,
        0x03, 0xEE,
        0x1C, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x18,
    };
    const pdu = try decode(&captured);
    var out: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try pdu.initiate_response.encode(false, &out));
}

test "conclude PDUs are two octets each" {
    var out: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAB, 0x00 }, try encodeConcludeRequest(&out));
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAC, 0x00 }, try encodeConcludeResponse(&out));
    try testing.expect((try decode(&[_]u8{ 0xAB, 0x00 })) == .conclude_request);
    try testing.expect((try decode(&[_]u8{ 0xAC, 0x00 })) == .conclude_response);
}

test "the captured confirmed-error for a missing file decodes" {
    // `a2 0a 80 01 01 a2 05 a0 03 8b 01 07` — errorClass file(11), code 7.
    const captured = [_]u8{ 0xA2, 0x0A, 0x80, 0x01, 0x01, 0xA2, 0x05, 0xA0, 0x03, 0x8B, 0x01, 0x07 };
    const pdu = try decode(&captured);
    try testing.expectEqual(@as(u32, 1), pdu.confirmed_error.invoke_id);
    try testing.expectEqual(ErrorClass.file, pdu.confirmed_error.error_class);
    try testing.expectEqual(@as(i32, 7), pdu.confirmed_error.code);
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try encodeConfirmedError(1, .file, 7, &out));
}

test "the captured FileDirectory request uses the long-form tag" {
    // `bf 4d 00` — service 77 needs the tag escape, and the body is empty.
    const captured = [_]u8{ 0xA0, 0x06, 0x02, 0x01, 0x01, 0xBF, 0x4D, 0x00 };
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try encodeFileDirectory(1, null, null, &out));
    const pdu = try decode(&captured);
    try testing.expectEqual(Service.file_directory, pdu.confirmed_request.service);
    try testing.expectEqual(@as(usize, 0), pdu.confirmed_request.body.len);
}

test "the captured FileOpen request is rebuilt octet for octet" {
    const captured = [_]u8{ 0xA0, 0x19, 0x02, 0x01, 0x01, 0xBF, 0x48, 0x13, 0xA0, 0x0E, 0x19, 0x0C } ++
        "IEDMODEL.CID".* ++ [_]u8{ 0x81, 0x01, 0x00 };
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try encodeFileOpen(1, "IEDMODEL.CID", 0, &out));
    const pdu = try decode(&captured);
    try testing.expectEqual(Service.file_open, pdu.confirmed_request.service);
}

test "FileRead and FileClose carry a bare Integer32" {
    var out: [32]u8 = undefined;
    const read = try encodeFileRead(7, 3, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA0, 0x07, 0x02, 0x01, 0x07, 0x9F, 0x49, 0x01, 0x03 }, read);
    const pdu = try decode(read);
    try testing.expectEqual(Service.file_read, pdu.confirmed_request.service);
    try testing.expectEqual(@as(i32, 3), try ber.decodeInt(i32, pdu.confirmed_request.body));

    var out2: [32]u8 = undefined;
    const close = try encodeFileClose(8, 3, &out2);
    try testing.expectEqual(Service.file_close, (try decode(close)).confirmed_request.service);
}

test "a FileRead response reports moreFollows and its data" {
    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try w.boolean(ber.Tag.ctx(1), false);
    try w.primitive(ber.Tag.ctx(0), "hello");
    try closeConfirmedResponse(&w, m, .file_read, 1);
    const pdu = try decode(w.done());
    const r = try decodeFileReadResponse(pdu.confirmed_response.body);
    try testing.expectEqualStrings("hello", r.data);
    try testing.expect(!r.more_follows);
}

test "the captured InformationReport (a real IEC 61850 report) decodes" {
    // Trimmed to its shape: RPT name plus three access results.
    const captured = [_]u8{
        0xA3, 0x1A, 0xA0, 0x18,
        0xA1, 0x05, 0x80, 0x03,
        'R',  'P',  'T',  0xA0,
        0x0F, 0x8A, 0x07, 'E',
        'v',  'e',  'n',  't',
        's',  '1',  0x86, 0x01,
        0x00, 0x83, 0x01, 0x01,
    };
    const pdu = try decode(&captured);
    try testing.expectEqual(UnconfirmedService.information_report, pdu.unconfirmed.service);
    var r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqualStrings("RPT", r.spec.variable_list.vmd_specific);
    try testing.expectEqualStrings("Events1", try (try r.results.next()).?.success.visibleString());
    try testing.expectEqual(@as(u32, 0), try (try r.results.next()).?.success.unsigned(u32));
    try testing.expectEqual(true, try (try r.results.next()).?.success.boolean());
    try testing.expect((try r.results.next()) == null);
}

test "an InformationReport is rebuilt octet for octet" {
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try mmsdata.Emit.boolean(&w, true);
    try mmsdata.Emit.unsigned(&w, 0);
    try mmsdata.Emit.visibleString(&w, "Events1");
    try closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = "RPT" } });
    const expected = [_]u8{
        0xA3, 0x1A, 0xA0, 0x18,
        0xA1, 0x05, 0x80, 0x03,
        'R',  'P',  'T',  0xA0,
        0x0F, 0x8A, 0x07, 'E',
        'v',  'e',  'n',  't',
        's',  '1',  0x86, 0x01,
        0x00, 0x83, 0x01, 0x01,
    };
    try testing.expectEqualSlices(u8, &expected, w.done());
}

test "named variable lists define, query and delete" {
    var out: [256]u8 = undefined;
    const members = [_]ObjectName{
        .{ .domain_specific = .{ .domain = test_domain, .item = "GGIO1$ST$Ind1$stVal" } },
        .{ .domain_specific = .{ .domain = test_domain, .item = "GGIO1$ST$Ind2$stVal" } },
    };
    const def = try encodeDefineNamedVariableList(
        1,
        .{ .domain_specific = .{ .domain = test_domain, .item = "LLN0$MyDS" } },
        &members,
        &out,
    );
    const pdu = try decode(def);
    try testing.expectEqual(Service.define_named_variable_list, pdu.confirmed_request.service);

    var out2: [128]u8 = undefined;
    const q = try encodeGetNamedVariableListAttributes(2, .{ .domain_specific = .{ .domain = test_domain, .item = "LLN0$MyDS" } }, &out2);
    try testing.expectEqual(Service.get_named_variable_list_attributes, (try decode(q)).confirmed_request.service);

    var out3: [128]u8 = undefined;
    const del = try encodeDeleteNamedVariableList(
        3,
        &[_]ObjectName{.{ .domain_specific = .{ .domain = test_domain, .item = "LLN0$MyDS" } }},
        &out3,
    );
    try testing.expectEqual(Service.delete_named_variable_list, (try decode(del)).confirmed_request.service);
}

test "the captured GetNamedVariableListAttributes response lists its members" {
    // `ac 24 a0 ... a1 ...` shape, trimmed to two members.
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    const list = w.mark();
    for ([_][]const u8{ "b", "a" }) |item| {
        const entry = w.mark();
        const spec = w.mark();
        try (ObjectName{ .domain_specific = .{ .domain = test_domain, .item = item } }).encode(&w);
        try w.header(ber.Tag.ctxc(0), spec);
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(ber.Tag.ctxc(1), list);
    try w.boolean(ber.Tag.ctx(0), false);
    try closeConfirmedResponse(&w, m, .get_named_variable_list_attributes, 1);

    const pdu = try decode(w.done());
    var attrs = try decodeGetNamedVariableListAttributesResponse(pdu.confirmed_response.body);
    try testing.expect(!attrs.deletable);
    try testing.expectEqualStrings("a", (try attrs.variables.next()).?.domain_specific.item);
    try testing.expectEqualStrings("b", (try attrs.variables.next()).?.domain_specific.item);
    try testing.expect((try attrs.variables.next()) == null);
}

test "Identify round trips" {
    var out: [128]u8 = undefined;
    const built = try encodeIdentifyResponse(1, .{ .vendor = "ACME", .model = "IED-1", .revision = "1.0" }, &out);
    const r = try decodeIdentifyResponse((try decode(built)).confirmed_response.body);
    try testing.expectEqualStrings("ACME", r.vendor);
    try testing.expectEqualStrings("IED-1", r.model);
    try testing.expectEqualStrings("1.0", r.revision);
    var out2: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA0, 0x05, 0x02, 0x01, 0x01, 0xA2, 0x00 }, try encodeIdentify(1, &out2));
}

test "a GetVariableAccessAttributes type tree walks with a depth bound" {
    // structure { componentName "stVal" : boolean, componentName "q" : bit-string }
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const resp = w.mark();
    const ts = w.mark();
    const comps = w.mark();
    for ([_]struct { name: []const u8, kind: u32 }{
        .{ .name = "q", .kind = 4 },
        .{ .name = "stVal", .kind = 3 },
    }) |c| {
        const entry = w.mark();
        const t = w.mark();
        try w.null_(ber.Tag.ctx(c.kind));
        try w.header(ber.Tag.ctxc(1), t);
        try w.primitive(ber.Tag.ctx(0), c.name);
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(ber.Tag.ctxc(1), comps);
    try w.header(ber.Tag.ctxc(2), ts); // TypeSpecification CHOICE = structure [2]
    // `typeSpecification [2]` is EXPLICIT because it holds a CHOICE, so the
    // alternative tag is wrapped a second time — exactly as a real IED emits it.
    try w.header(ber.Tag.ctxc(2), ts);
    try w.boolean(ber.Tag.ctx(0), false);
    try closeConfirmedResponse(&w, resp, .get_variable_access_attributes, 1);

    const pdu = try decode(w.done());
    const attrs = try decodeGetVariableAccessAttributesResponse(pdu.confirmed_response.body);
    try testing.expect(attrs.type_spec.isStructure());
    try attrs.type_spec.validate();
    var it = try attrs.type_spec.components();
    const first = (try it.next()).?;
    try testing.expectEqualStrings("stVal", first.name.?);
    try testing.expectEqual(@as(u32, 3), first.type_spec.kind);
    try testing.expectEqualStrings("q", (try it.next()).?.name.?);
}

test "malformed PDUs are typed errors" {
    try testing.expectError(error.UnknownPdu, decode(&[_]u8{ 0x30, 0x00 }));
    try testing.expectError(error.UnknownPdu, decode(&[_]u8{ 0xBF, 0x7F, 0x00 }));
    // A confirmed request with no service.
    try testing.expectError(error.MissingField, decode(&[_]u8{ 0xA0, 0x03, 0x02, 0x01, 0x01 }));
    // A confirmed request whose invoke id is not an INTEGER.
    try testing.expectError(error.UnexpectedTag, decode(&[_]u8{ 0xA0, 0x02, 0x05, 0x00 }));
    // A read response with no listOfAccessResult.
    try testing.expectError(error.MissingField, decodeReadResponse(&[_]u8{}));
    // An access-result list whose member is not a Data alternative.
    var r = try decodeReadResponse(&[_]u8{ 0xA1, 0x02, 0x30, 0x00 });
    try testing.expectError(error.UnknownDataType, r.results.next());
}

test "a reject PDU is surfaced rather than parsed as a response" {
    const bytes = [_]u8{ 0xA4, 0x06, 0x80, 0x01, 0x05, 0x81, 0x01, 0x01 };
    const pdu = try decode(&bytes);
    try testing.expectEqual(@as(u32, 5), pdu.reject.invoke_id.?);
    try testing.expectEqual(@as(u32, 1), pdu.reject.reject_reason_class);
}

test "fuzz: mms decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const pdu = decode(buf[0..len]) catch return;
    switch (pdu) {
        .confirmed_request => |r| {
            _ = decodeReadRequest(r.body) catch {};
            _ = decodeWriteRequest(r.body) catch {};
            _ = decodeGetNameListRequest(r.body) catch {};
            _ = decodeFileOpenResponse(r.body) catch {};
        },
        .confirmed_response => |r| {
            if (decodeReadResponse(r.body)) |*rr| {
                var it = rr.results;
                var guard: usize = 0;
                while (it.next() catch null) |_| {
                    guard += 1;
                    if (guard > buf.len) return error.TestUnexpectedResult;
                }
            } else |_| {}
            if (decodeGetNameListResponse(r.body)) |*gr| {
                var it = gr.names;
                var guard: usize = 0;
                while (it.next() catch null) |_| {
                    guard += 1;
                    if (guard > buf.len) return error.TestUnexpectedResult;
                }
            } else |_| {}
            _ = decodeFileDirectoryResponse(r.body) catch {};
            _ = decodeGetVariableAccessAttributesResponse(r.body) catch {};
        },
        .unconfirmed => |u| {
            if (decodeInformationReport(u.body)) |*ir| {
                var it = ir.results;
                var guard: usize = 0;
                while (it.next() catch null) |_| {
                    guard += 1;
                    if (guard > buf.len) return error.TestUnexpectedResult;
                }
            } else |_| {}
        },
        else => {},
    }
}
