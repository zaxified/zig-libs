// SPDX-License-Identifier: MIT

//! iec61850 — pure-Zig **substation automation**: the IEC 61850 MMS stack an
//! IED and a SCADA client speak on TCP port 102, plus **GOOSE**, the
//! layer-2 multicast protocol protection schemes trip breakers with.
//!
//! Two halves that share only a BER codec:
//!
//! * **MMS (the slow half).** The full OSI sandwich IEC 61850-8-1 puts under
//!   ISO 9506: `tpkt` (RFC 1006) → `cotp` (ISO 8073 class 0) → `session`
//!   (ISO 8327 CONNECT/ACCEPT) → `presentation` (ISO 8823 CP/CPA with the
//!   **presentation context definition list**) → `acse` (AARQ/AARE) → `mms`.
//!   On top: the `Data` type, the ACSI object-reference syntax in both its
//!   forms, reporting control blocks, and a client and a server.
//! * **The control model (IEC 61850-7-2 §20).** All four `ctlModel`s,
//!   `Oper`/`SBO`/`SBOw`/`Cancel`, `AddCause`, `LastApplError` and the
//!   `CommandTermination` that arrives *after* the write response — plus a pure,
//!   time-injected state machine on each side.
//! * **SCL (IEC 61850-6).** The configuration language, parsed with the `xml`
//!   sibling, and — the real deliverable — a resolver that walks
//!   `LN → LNodeType → DOType → DAType` and produces the flat list of MMS names
//!   the wire uses.
//! * **GOOSE (the fast half).** The Ethernet frame with its optional 802.1Q
//!   tag, the BER PDU, and — the part worth the trouble — the **retransmission
//!   state machines**: a publisher that walks a backoff ladder after a state
//!   change and always advertises a `timeAllowedtoLive` longer than its next
//!   transmission, and a subscriber that turns the resulting stream into typed
//!   events (state change, sequence gap, TAL expiry, `confRev` mismatch). Both
//!   are **pure and time-injected** — the caller supplies "now" — so the whole
//!   thing is testable with no network at all.
//!
//! `sv` (IEC 61850-9-2 sampled values) is here too: it fell out of the same
//! frame and BER work.
//!
//! Verified against **real traffic between two independent third-party
//! implementations** and by **live round trips in both directions**; see
//! `goldens.zig` and SPEC.md for exactly which frames came from where and what
//! is self-derived.
//!
//! Provenance: clean-room from the published ISO 8073 / RFC 1006 / ISO 8327 /
//! ISO 8823 / ISO 8650 / ISO 9506 / IEC 61850-8-1 layouts. No third-party
//! source was read as a design reference; a third-party stack was built and run
//! **as a black box** — to generate wire traffic and to act as a live peer —
//! which is a test oracle, not a design reference. See SPEC.md.

const std = @import("std");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IEC 61850 substation automation — MMS (ISO 9506) client over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe + SV sampled values",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // Codecs, state machines, client PDU logic and the responder are pure
    // computation; only the optional TcpTransport touches std.Io.net.
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // client + server, publisher + subscriber
    // One Client/Server owns one association's buffers and invoke ids; one
    // Publisher/Subscriber owns one control block's counters. Nothing shared,
    // no clock, no thread — those are the caller's.
    .concurrency = .single_owner,
    .model_after = "ISO 9506 (MMS) as profiled by IEC 61850-8-1, over ISO 8073/8327/8823/8650, plus the IEC 61850-7-2 control model and IEC 61850-6 SCL; wire behaviour cross-checked against captured traffic between two independent third-party stacks, against the Wireshark mms/goose dissectors, and — for SCL — against the GetNameList of the IEDs the parsed files configure (see SPEC.md)",
    // `xml` is used by `scl` alone; every other file here is std-only.
    .deps = .{"xml"},
};

// ── layers ──────────────────────────────────────────────────────────────────

/// BER (X.690): tags, lengths, the indefinite form, and a backwards writer.
pub const ber = @import("ber.zig");
/// TPKT (RFC 1006 §6) and a stream framer.
pub const tpkt = @import("tpkt.zig");
/// COTP (ISO 8073 class 0) with segment reassembly.
pub const cotp = @import("cotp.zig");
/// The ISO 8327 session layer: CONNECT/ACCEPT and the data-transfer prefix.
pub const session = @import("session.zig");
/// The ISO 8823 presentation layer and the context definition list.
pub const presentation = @import("presentation.zig");
/// ACSE (ISO 8650): AARQ/AARE/RLRQ/RLRE/ABRT.
pub const acse = @import("acse.zig");
/// The MMS `Data` type, bounded-depth.
pub const mmsdata = @import("mmsdata.zig");
/// MMS PDUs and the services IEC 61850-8-1 profiles.
pub const mms = @import("mms.zig");
/// ACSI object references and functional constraints.
pub const acsi = @import("acsi.zig");
/// Report control blocks and the reports they emit.
pub const report = @import("report.zig");
/// The **server side** of reporting: live control blocks, buffering and the
/// report encoder.
pub const reporting = @import("reporting.zig");
/// The control model: `Oper`/`SBO`/`SBOw`/`Cancel`, `AddCause`,
/// `LastApplError` and the select-before-operate state machines.
pub const control = @import("control.zig");
/// Logging (IEC 61850-7-2 §18): the log control block, the bounded log store
/// and the MMS journal services.
pub const logging = @import("logging.zig");
/// Setting groups (IEC 61850-7-2 §19): the SGCB and the edit-then-confirm
/// services.
pub const settinggroups = @import("settinggroups.zig");
/// SCL (IEC 61850-6): the substation configuration language, and the type
/// resolution that turns it into the object model the MMS layer addresses.
pub const scl = @import("scl.zig");
/// Emitting SCL: serialising a model back to an `ICD`/`CID` document.
pub const sclwrite = @import("sclwrite.zig");
/// GOOSE frames and PDUs.
pub const goose = @import("goose.zig");
/// The GOOSE publisher state machine.
pub const publisher = @import("publisher.zig");
/// The GOOSE subscriber state machine.
pub const subscriber = @import("subscriber.zig");
/// Sampled values (IEC 61850-9-2).
pub const sv = @import("sv.zig");
/// The byte-stream and layer-2 seams, and their adapters.
pub const transport = @import("transport.zig");
/// An IEC 61850 MMS client.
pub const client = @import("client.zig");
/// An IEC 61850 MMS server.
pub const server = @import("server.zig");
/// Byte-exact frames captured from third-party traffic.
pub const goldens = @import("goldens.zig");
/// Byte-exact **control-model** frames captured from real traffic.
pub const controlgoldens = @import("controlgoldens.zig");

// ── top-level names (the ones a consumer actually types) ────────────────────

pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const ReportHandler = client.ReportHandler;

pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const Model = server.Model;
pub const Variable = server.Variable;
pub const DataSet = server.DataSet;
pub const ServerControlPoint = server.ControlPoint;

pub const Publisher = publisher.Publisher;
pub const PublisherConfig = publisher.Config;
pub const Profile = publisher.Profile;
pub const Subscriber = subscriber.Subscriber;
pub const SubscriberConfig = subscriber.Config;
pub const Event = subscriber.Event;

pub const Transport = transport.Transport;
pub const TransportError = transport.TransportError;
pub const TcpTransport = transport.TcpTransport;
pub const LoopTransport = transport.LoopTransport;
pub const Link = transport.Link;
pub const LinkError = transport.LinkError;
pub const LoopLink = transport.LoopLink;
pub const default_port = transport.default_port;

pub const Data = mmsdata.Data;
pub const DataKind = mmsdata.Kind;
pub const UtcTime = mmsdata.UtcTime;
pub const BinaryTime = mmsdata.BinaryTime;
pub const Emit = mmsdata.Emit;

pub const ObjectName = mms.ObjectName;
pub const ObjectReference = acsi.ObjectReference;
pub const FunctionalConstraint = acsi.FunctionalConstraint;
pub const parseAcsi = acsi.parseAcsi;
pub const parseMms = acsi.parseMms;

pub const ReportControl = server.ReportControl;
pub const LogControl = server.LogControl;
pub const SettingGroups = server.SettingGroups;
pub const ReportTrigger = reporting.Trigger;
pub const ReportBuffer = reporting.Buffer;
pub const LogStore = logging.Store;
pub const Setting = settinggroups.Setting;

pub const Rcb = report.Rcb;
pub const Report = report.Report;
pub const OptFlds = report.OptFlds;
pub const TrgOps = report.TrgOps;
/// Puts a segmented report back together on the client side.
pub const ReportReassembler = report.Reassembler;
pub const AssembledReport = report.Assembled;
pub const JournalLimit = logging.Limit;

pub const ControlMachine = control.Machine;
pub const ControlPoint = control.Point;
pub const ControlCommand = control.Command;
pub const CtlModel = control.CtlModel;
pub const AddCause = control.AddCause;
pub const LastApplError = control.LastApplError;
pub const ControlNotification = control.Notification;
pub const ControlHandler = client.ControlHandler;

pub const Scl = scl.Scl;
pub const SclModel = scl.Model;
pub const emitScl = sclwrite.emitParsed;
pub const SclDocument = sclwrite.Document;
pub const parseScl = scl.parse;
pub const resolveScl = scl.resolve;

pub const GooseFrame = goose.Frame;
pub const GoosePdu = goose.Pdu;
pub const Vlan = goose.Vlan;
pub const SavPdu = sv.SavPdu;
pub const Asdu = sv.Asdu;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = ber;
    _ = tpkt;
    _ = cotp;
    _ = session;
    _ = presentation;
    _ = acse;
    _ = mmsdata;
    _ = mms;
    _ = acsi;
    _ = report;
    _ = reporting;
    _ = logging;
    _ = settinggroups;
    _ = control;
    _ = scl;
    _ = sclwrite;
    _ = goose;
    _ = publisher;
    _ = subscriber;
    _ = sv;
    _ = transport;
    _ = client;
    _ = server;
    _ = goldens;
    _ = controlgoldens;
    _ = @import("bench.zig");
}

// ── tests: the whole stack, client against server ──────────────────────────

const testing = std.testing;

test "meta.deps names the one module this one is built on" {
    // SCL is XML, and the sibling `xml` module is a hardened, C14N-grade parser
    // built for XML-DSig. Writing a second one here would be a worse parser and
    // a second attack surface.
    try testing.expectEqual(@as(usize, 1), meta.deps.len);
    try testing.expectEqualStrings("xml", meta.deps[0]);
}

test "the MMS and GOOSE halves share one BER codec" {
    // A `Data` value built for a GOOSE data set decodes identically when it
    // arrives as an MMS access result, which is the whole reason `mmsdata` is
    // not two files.
    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try Emit.float(&w, 50.02);
    const value = w.done();

    const p = goose.Pdu{
        .gocb_ref = "LD/LLN0$GO$gcb",
        .time_allowed_to_live_ms = 2000,
        .dat_set = "LD/LLN0$ds",
        .go_id = "gcb",
        .t = UtcTime.fromMillis(1_700_000_000_000, 10),
        .st_num = 1,
        .sq_num = 0,
        .test_mode = false,
        .conf_rev = 1,
        .nds_com = false,
        .num_dat_set_entries = 1,
        .all_data = &.{},
    };
    var pbuf: [256]u8 = undefined;
    const decoded = try goose.Pdu.decode(try p.encode(&[_][]const u8{value}, &pbuf));
    var it = decoded.values();
    try testing.expectApproxEqAbs(@as(f64, 50.02), try (try it.next()).?.asFloat(), 1e-4);

    var rbuf: [256]u8 = undefined;
    var rw = ber.Writer.init(&rbuf);
    const m = rw.mark();
    try rw.bytes(value);
    try mms.closeReadResponse(&rw, m, 1);
    const resp = (try mms.decode(rw.done())).confirmed_response;
    var rr = try mms.decodeReadResponse(resp.body);
    try testing.expectApproxEqAbs(@as(f64, 50.02), try (try rr.results.next()).?.success.asFloat(), 1e-4);
}

test "an ACSI reference survives a whole client-side round trip" {
    var item: [128]u8 = undefined;
    const name = try acsi.objectNameFor("simpleIOGenericIO/GGIO1.AnIn1.mag.f", .MX, &item);
    try testing.expectEqualStrings("GGIO1$MX$AnIn1$mag$f", name.domain_specific.item);
    const back = try acsi.parseMmsParts(name.domain_specific.domain, name.domain_specific.item);
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("simpleIOGenericIO/GGIO1.AnIn1.mag.f", try back.toAcsi(&out));
    try testing.expectEqual(FunctionalConstraint.MX, back.fc.?);
}

test "a GOOSE subscriber configured from SCL accepts the publisher SCL describes" {
    // The cross-check the whole SCL layer exists for: the configuration file
    // says what the publisher will send, and the GOOSE decoder must agree.
    // Nothing here is hand-wired — every string comes out of the document.
    var doc = try scl.parse(testing.allocator, scl.sample, .{});
    defer doc.deinit();
    var model = try scl.resolve(&doc, testing.allocator, "TESTIED");
    defer model.deinit();

    const ied = doc.ied("TESTIED").?;
    const ld = ied.access_points[0].devices[0];
    const ln0 = ld.lns[0];
    const gcb = ln0.gse_controls[0];

    var domain_buf: [64]u8 = undefined;
    const domain = try ld.domain(ied.name, &domain_buf);
    var ln_buf: [64]u8 = undefined;
    const ln_name = try ln0.mmsName(&ln_buf);

    var gocb_buf: [128]u8 = undefined;
    const gocb_ref = try scl.controlBlockRef(domain, ln_name, .GO, gcb.name, &gocb_buf);
    try testing.expectEqualStrings("TESTIEDGenericIO/LLN0$GO$gcbEvents", gocb_ref);
    // The control block really is in the resolved name space.
    var item_buf: [128]u8 = undefined;
    try testing.expect(model.has(domain, try std.fmt.bufPrint(&item_buf, "{s}$GO${s}", .{ ln_name, gcb.name })));

    // The data set it publishes, and the members it will carry.
    var ds: ?scl.DataSet = null;
    for (ln0.data_sets) |d| {
        if (std.mem.eql(u8, d.name, gcb.dat_set)) ds = d;
    }
    var ds_buf: [128]u8 = undefined;
    const dat_set = try scl.dataSetRef(domain, ln_name, ds.?.name, &ds_buf);
    try testing.expectEqualStrings("TESTIEDGenericIO/LLN0$Events", dat_set);

    // Every FCDA must name something the resolver produced, or the publisher
    // will send values for objects the subscriber cannot map.
    for (ds.?.fcdas) |f| {
        var fbuf: [128]u8 = undefined;
        try testing.expect(model.has(domain, try f.mmsItem(&fbuf)));
    }

    // The layer-2 parameters come from `Communication`, not from the control
    // block, and the frame is built with exactly those.
    const addr = doc.cbAddress(ied.name, ld.inst, gcb.name).?;
    var values: [8]u8 = undefined;
    var vw = ber.Writer.init(&values);
    try Emit.boolean(&vw, true);

    const pdu = GoosePdu{
        .gocb_ref = gocb_ref,
        .time_allowed_to_live_ms = addr.max_time_ms.? * 2,
        .dat_set = dat_set,
        .go_id = gcb.app_id,
        .t = UtcTime.fromMillis(1_700_000_000_000, 10),
        .st_num = 1,
        .sq_num = 0,
        .test_mode = false,
        .conf_rev = gcb.conf_rev,
        .nds_com = false,
        .num_dat_set_entries = @intCast(ds.?.fcdas.len),
        .all_data = &.{},
    };
    var pdu_buf: [512]u8 = undefined;
    const encoded = try pdu.encode(&[_][]const u8{vw.done()}, &pdu_buf);

    var frame_buf: [512]u8 = undefined;
    const template = GooseFrame{
        .dst = .{ 0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01 },
        .src = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .vlan = .{ .id = addr.address.vlanId().?, .priority = addr.address.vlanPriority().? },
        .appid = addr.address.appId().?,
        .pdu = encoded,
        .total_len = 0,
    };
    const frame = try template.encode(encoded, &frame_buf);

    // And the decoder agrees, field for field, with what the file said.
    const decoded_frame = try GooseFrame.decode(frame);
    try testing.expectEqual(@as(u16, 1000), decoded_frame.appid);
    try testing.expectEqual(@as(u12, 100), decoded_frame.vlan.?.id);
    const decoded = try GoosePdu.decode(decoded_frame.pdu);
    try testing.expectEqualStrings(gocb_ref, decoded.gocb_ref);
    try testing.expectEqualStrings(dat_set, decoded.dat_set);
    try testing.expectEqual(gcb.conf_rev, decoded.conf_rev);
    try testing.expectEqual(@as(u32, @intCast(ds.?.fcdas.len)), decoded.num_dat_set_entries);

    // A subscriber configured straight from the file binds to it.
    var sub = Subscriber.init(.{ .gocb_ref = gocb_ref, .expected_conf_rev = gcb.conf_rev });
    try testing.expect(sub.matches(decoded));
    const ev = sub.onFrame(decoded, 0);
    try testing.expect(!ev.has(.conf_rev_mismatch));
    try testing.expect(sub.dataUsable());

    // …and one configured from a *stale* copy of the file does not, which is
    // the failure `confRev` exists to catch.
    var stale = Subscriber.init(.{ .gocb_ref = gocb_ref, .expected_conf_rev = gcb.conf_rev - 1 });
    try testing.expect(stale.onFrame(decoded, 0).has(.conf_rev_mismatch));
}

// ── live interop ────────────────────────────────────────────────────────────
//
// All three print `SKIPPED: …` and pass when no peer is present.

fn envVar(name: []const u8) ?[]const u8 {
    return testkit.getEnv(name);
}

const Endpoint = struct { host: []const u8, port: u16 };

fn splitEndpoint(endpoint: []const u8) ?Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;
    return .{ .host = endpoint[0..colon], .port = port };
}

var live_reports: usize = 0;
var live_report_entries: usize = 0;

fn onLiveReport(_: *anyopaque, r: *const Report) void {
    live_reports += 1;
    live_report_entries += r.entry_count;
}

// Set IEC61850_TEST_SERVER=host:port to run a real round trip against a live
// IEC 61850 server. IEC61850_TEST_LD names the logical device to browse
// (default `simpleIOGenericIO`).
test "live: our client against a real IEC 61850 server" {
    const endpoint = envVar("IEC61850_TEST_SERVER") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 client (set IEC61850_TEST_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const ld = envVar("IEC61850_TEST_LD") orelse "simpleIOGenericIO";

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 client (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(3000);

    var buf: [131072]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{});
    try c.connect();
    defer c.disconnect();

    // 1. Server directory: the logical devices.
    var names: [512][]const u8 = undefined;
    const ld_count = try c.getServerDirectory(&names);
    try testing.expect(ld_count > 0);

    // 2. Every named variable of one logical device — a 6 kB reply on a real
    //    IED, which exercises the two-octet BER length live.
    const var_count = try c.getLogicalDeviceDirectory(ld, &names);

    // 3. Data sets.
    const ds_count = try c.getDataSetDirectory(ld, &names);

    // 4. Read a measurement and a status point.
    var ref_buf: [128]u8 = undefined;
    const mag_ref = try std.fmt.bufPrint(&ref_buf, "{s}/GGIO1.AnIn1.mag.f", .{ld});
    const mag = try c.readObject(mag_ref, .MX);
    const mag_value = try mag.asFloat();

    var ref_buf2: [128]u8 = undefined;
    const ind_ref = try std.fmt.bufPrint(&ref_buf2, "{s}/GGIO1.Ind1.stVal", .{ld});
    _ = try (try c.readObject(ind_ref, .ST)).boolean();

    // 5. Write a description string and read it back.
    var ref_buf3: [128]u8 = undefined;
    const vendor_ref = try std.fmt.bufPrint(&ref_buf3, "{s}/GGIO1.NamPlt.vendor", .{ld});
    var vbuf: [64]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try Emit.visibleString(&vw, "zig-libs");
    var write_ok = true;
    c.writeObject(vendor_ref, .DC, vw.done()) catch {
        write_ok = false;
    };
    var readback_ok = false;
    if (write_ok) {
        const back = try c.readObject(vendor_ref, .DC);
        readback_ok = std.mem.eql(u8, try back.visibleString(), "zig-libs");
    }

    // 6. A variable that does not exist must come back as a per-object failure,
    //    not as a fatal error.
    var ref_buf4: [128]u8 = undefined;
    const bogus = try std.fmt.bufPrint(&ref_buf4, "{s}/GGIO1.NoSuchThing.stVal", .{ld});
    try testing.expectError(error.AccessFailed, c.readObject(bogus, .ST));

    // 7. Read a whole data set in one request.
    var ds_ref: [128]u8 = undefined;
    const ds = try std.fmt.bufPrint(&ds_ref, "{s}/LLN0$Events", .{ld});
    var ds_values: usize = 0;
    if (c.readDataSet(ds)) |it_const| {
        var it = it_const;
        while (it.next() catch null) |_| ds_values += 1;
    } else |_| {}

    // 8. The unbuffered report control block: read it, enable it, ask for a
    //    general interrogation, and receive the report the IED pushes.
    var rcb_ref: [128]u8 = undefined;
    const rcb_name = try std.fmt.bufPrint(&rcb_ref, "{s}/LLN0.EventsRCB01", .{ld});
    live_reports = 0;
    live_report_entries = 0;
    var dummy: u8 = 0;
    c.setReportHandler(.{ .ctx = &dummy, .on_report = onLiveReport });

    var rcb_ok = false;
    if (c.readRcb(rcb_name, .unbuffered)) |rcb| {
        rcb_ok = rcb.dat_set.len > 0;
        c.enableReporting(rcb_name, .unbuffered, .{ .data_change = true, .general_interrogation = true }, 1000) catch {};
        c.generalInterrogation(rcb_name, .unbuffered) catch {};
        var rounds: usize = 0;
        while (rounds < 20 and live_reports == 0) : (rounds += 1) {
            _ = c.poll() catch break;
        }
        c.disableReporting(rcb_name, .unbuffered) catch {};
    } else |_| {}

    // 9. Identify, if the server implements it.
    var vendor: []const u8 = "(unsupported)";
    if (c.identify()) |ident| {
        vendor = ident.vendor;
    } else |_| {}

    std.debug.print(
        "live IEC 61850 client: lds={d} vars={d} datasets={d} mag={d:.4} write={} readback={} " ++
            "dataset_values={d} rcb={} reports={d} report_entries={d} vendor={s}\n",
        .{ ld_count, var_count, ds_count, mag_value, write_ok, readback_ok, ds_values, rcb_ok, live_reports, live_report_entries, vendor },
    );
    try testing.expect(ld_count > 0 and var_count > 50);
}

var live_notifications: usize = 0;
var live_last_kind: ?control.NotificationKind = null;
var live_last_cause: ?control.AddCause = null;

fn onLiveNotification(_: *anyopaque, n: control.Notification) void {
    live_notifications += 1;
    live_last_kind = n.kind;
    live_last_cause = n.addCause();
}

// Set IEC61850_TEST_CONTROL=host:port to drive the **control model** against a
// live IEC 61850 server that has controllable objects (the reference stack's
// control example serves `SPCSO1`..`SPCSO9` with one ctlModel each).
// IEC61850_TEST_CONTROL_LD names the logical device.
test "live: our client operating a real IED through every control model" {
    const endpoint = envVar("IEC61850_TEST_CONTROL") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 control (set IEC61850_TEST_CONTROL=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const ld = envVar("IEC61850_TEST_CONTROL_LD") orelse "simpleIOGenericIO";

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 control (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(3000);

    var buf: [131072]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{});
    try c.connect();
    defer c.disconnect();

    var dummy: u8 = 0;
    c.setControlHandler(.{ .ctx = &dummy, .on_notification = onLiveNotification });
    live_notifications = 0;

    var value: [8]u8 = undefined;
    var vw = ber.Writer.init(&value);
    try Emit.boolean(&vw, true);
    const on = vw.done();

    // The four objects the reference control model advertises, one per
    // ctlModel. Each is driven through the whole state machine, and the
    // resulting `stVal` is read back over MMS — so the assertion is that the
    // *IED* moved, not that our write returned.
    const objects = [_][]const u8{ "SPCSO1", "SPCSO2", "SPCSO3", "SPCSO4" };
    var operated: usize = 0;
    var models: [4]control.CtlModel = undefined;
    var terminations: usize = 0;
    for (objects, 0..) |obj, i| {
        var ref_buf: [128]u8 = undefined;
        const ref = try std.fmt.bufPrint(&ref_buf, "{s}/GGIO1.{s}", .{ ld, obj });
        models[i] = try c.readCtlModel(ref);
        const sbo_timeout = (try c.readSboTimeout(ref)) orelse 2000;

        var m = control.Machine.init(models[i], sbo_timeout);
        const before = live_notifications;
        c.executeControl(&m, ref, .{
            .ctl_val = on,
            .origin = .{ .or_cat = .station_control, .or_ident = "zig-libs" },
            .t = UtcTime.fromMillis(1_700_000_000_000, 10),
        }, 0) catch |e| {
            std.debug.print("live control: {s} model={s} failed: {t} add_cause={?s}\n", .{
                obj,
                @tagName(models[i]),
                e,
                if (m.failure) |f| (if (f.add_cause) |a| a.name() else null) else null,
            });
            continue;
        };
        if (m.state != .succeeded) continue;
        operated += 1;
        if (models[i].isEnhanced() and live_notifications > before) terminations += 1;

        // And the status point really moved.
        var st_buf: [128]u8 = undefined;
        const st = try std.fmt.bufPrint(&st_buf, "{s}/GGIO1.{s}.stVal", .{ ld, obj });
        try testing.expect(try (try c.readObject(st, .ST)).boolean());
    }

    // The failure path: operate a select-before-operate object without
    // selecting it. A real IED answers with a `LastApplError` naming
    // `Object-not-selected`, which is the field this module exists to surface.
    var bad_buf: [128]u8 = undefined;
    const bad_ref = try std.fmt.bufPrint(&bad_buf, "{s}/GGIO1.SPCSO4", .{ld});
    var refused_cause: ?control.AddCause = null;
    live_last_cause = null;
    c.operateObject(bad_ref, .{
        .ctl_val = on,
        .ctl_num = 200,
        .origin = .{ .or_cat = .station_control, .or_ident = "zig-libs" },
        .t = UtcTime.fromMillis(1_700_000_000_000, 10),
    }) catch {
        refused_cause = c.lastAddCause();
    };

    std.debug.print(
        "live IEC 61850 control: models={s}/{s}/{s}/{s} operated={d} terminations={d} " ++
            "notifications={d} unselected_operate_add_cause={?s}\n",
        .{
            @tagName(models[0]), @tagName(models[1]), @tagName(models[2]), @tagName(models[3]),
            operated,            terminations,        live_notifications,  if (refused_cause) |r| r.name() else null,
        },
    );
    try testing.expectEqual(@as(usize, 4), operated);
    // Both enhanced-security objects owed a CommandTermination and sent one.
    try testing.expect(terminations >= 2);
    try testing.expect(refused_cause != null);
}

// The SCL round trip that matters: parse the **same configuration file** a real
// IED was built from, resolve its type graph, and compare the resulting MMS
// names against what that IED reports over the wire.
//
//   IEC61850_TEST_SCL_FILE=<path to .icd/.cid>
//   IEC61850_TEST_SCL_SERVER=host:port
//   IEC61850_TEST_SCL_IED=<IED name>   (default: the file's only IED)
test "live: an SCL file resolves to exactly the names the IED it configures serves" {
    const path = envVar("IEC61850_TEST_SCL_FILE") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL round trip (set IEC61850_TEST_SCL_FILE=<path>)\n", .{});
        return error.SkipZigTest;
    };
    const endpoint = envVar("IEC61850_TEST_SCL_SERVER") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL round trip (set IEC61850_TEST_SCL_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const source = try std.Io.Dir.cwd().readFileAlloc(io, path, testing.allocator, .limited(1 << 22));
    defer testing.allocator.free(source);

    // IEC 61850-8-1 spells the BRCB timestamp `TimeOfEntry`; a widely deployed
    // stack spells it `TimeofEntry`. `IEC61850_TEST_SCL_TIMEOFENTRY` supplies
    // the spelling the IED under test uses, which is why the resolver takes the
    // BRCB attribute list as an option rather than hard-coding one.
    var brcb: [scl.default_brcb_attributes.len][]const u8 = undefined;
    for (scl.default_brcb_attributes, 0..) |a, i| {
        brcb[i] = if (std.mem.eql(u8, a, "TimeOfEntry"))
            (envVar("IEC61850_TEST_SCL_TIMEOFENTRY") orelse a)
        else
            a;
    }
    // Likewise `ResvTms`: edition 2's optional SGCB reservation attribute.
    var sgcb: [scl.default_sgcb_attributes.len + 1][]const u8 = undefined;
    for (scl.default_sgcb_attributes, 0..) |a, i| sgcb[i] = a;
    sgcb[scl.default_sgcb_attributes.len] = "ResvTms";
    const sgcb_len: usize = if (envVar("IEC61850_TEST_SCL_RESVTMS") != null)
        sgcb.len
    else
        scl.default_sgcb_attributes.len;

    var doc = try scl.parse(testing.allocator, source, .{
        .allow_unknown_btype = true,
        .brcb_attributes = &brcb,
        .sgcb_attributes = sgcb[0..sgcb_len],
    });
    defer doc.deinit();
    const ied_name = envVar("IEC61850_TEST_SCL_IED") orelse doc.ieds[0].name;
    var model = try scl.resolve(&doc, testing.allocator, ied_name);
    defer model.deinit();

    // The live IED.
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL round trip (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(3000);
    var buf: [262144]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{});
    try c.connect();
    defer c.disconnect();

    var domain_slices: [64][]const u8 = undefined;
    const domain_count = try c.getServerDirectory(&domain_slices);
    // Every decoded name points into the reassembly buffer, which the next
    // request reuses — so the domains are copied out before anything else is
    // asked of the IED.
    var domains: std.ArrayList([]u8) = .empty;
    defer {
        for (domains.items) |x| testing.allocator.free(x);
        domains.deinit(testing.allocator);
    }
    for (domain_slices[0..domain_count]) |name| {
        try domains.append(testing.allocator, try testing.allocator.dupe(u8, name));
    }

    var missing: usize = 0; // served by the IED, not produced by the resolver
    var extra: usize = 0; // produced by the resolver, not served by the IED
    var matched: usize = 0;
    var live_total: usize = 0;
    var first_missing_buf: [256]u8 = undefined;
    var first_missing: []const u8 = "";
    var first_extra_buf: [256]u8 = undefined;
    var first_extra: []const u8 = "";

    var d: usize = 0;
    while (d < domain_count) : (d += 1) {
        // The names have to be copied: `getLogicalDeviceDirectory` hands back
        // slices into the reassembly buffer, which the next request reuses.
        var live_names: [2048][]const u8 = undefined;
        const n = try c.getLogicalDeviceDirectory(domains.items[d], &live_names);
        var owned: std.ArrayList([]u8) = .empty;
        defer {
            for (owned.items) |s| testing.allocator.free(s);
            owned.deinit(testing.allocator);
        }
        for (live_names[0..n]) |name| {
            try owned.append(testing.allocator, try testing.allocator.dupe(u8, name));
        }
        const domain = domains.items[d];
        live_total += owned.items.len;

        for (owned.items) |name| {
            if (model.has(domain, name)) {
                matched += 1;
            } else {
                if (envVar("IEC61850_TEST_SCL_VERBOSE") != null) {
                    std.debug.print("  only on IED: {s}/{s}\n", .{ domain, name });
                }
                if (first_missing.len == 0 and name.len <= first_missing_buf.len) {
                    @memcpy(first_missing_buf[0..name.len], name);
                    first_missing = first_missing_buf[0..name.len];
                }
                missing += 1;
            }
        }
        for (model.nodes) |node| {
            if (!std.mem.eql(u8, node.domain, domain)) continue;
            var found = false;
            for (owned.items) |name| {
                if (std.mem.eql(u8, name, node.item)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (envVar("IEC61850_TEST_SCL_VERBOSE") != null) {
                    std.debug.print("  only in model: {s}/{s}\n", .{ domain, node.item });
                }
                if (first_extra.len == 0 and node.item.len <= first_extra_buf.len) {
                    @memcpy(first_extra_buf[0..node.item.len], node.item);
                    first_extra = first_extra_buf[0..node.item.len];
                }
                extra += 1;
            }
        }
    }

    std.debug.print(
        "live SCL round trip: file={s} ied={s} resolved={d} live={d} matched={d} " ++
            "only_on_ied={d}{s}{s} only_in_model={d}{s}{s}\n",
        .{
            std.fs.path.basename(path),        ied_name,      model.nodes.len,
            live_total,                        matched,       missing,
            if (missing > 0) " e.g. " else "", first_missing, extra,
            if (extra > 0) " e.g. " else "",   first_extra,
        },
    );
    // The claim: the resolver reproduces the IED's own name space exactly.
    try testing.expect(live_total > 100);
    try testing.expectEqual(@as(usize, 0), missing);
    try testing.expectEqual(@as(usize, 0), extra);
}

// Set IEC61850_TEST_LISTEN_CONTROL=host:port and point a real IEC 61850
// **control** client at it. The model mirrors the reference control example:
// four `SPCSO` objects, one per ctlModel, each with its `ctlModel` under `CF`
// and its `stVal` under `ST`.
test "live: a real IEC 61850 client operating our control objects" {
    const endpoint = envVar("IEC61850_TEST_LISTEN_CONTROL") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live control server (set IEC61850_TEST_LISTEN_CONTROL=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live control server (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live control server listening on {s}\n", .{endpoint});

    const ld = envVar("IEC61850_TEST_LISTEN_LD") orelse "simpleIOGenericIO";
    const models = [_]control.CtlModel{
        .direct_with_normal_security,
        .sbo_with_normal_security,
        .direct_with_enhanced_security,
        .sbo_with_enhanced_security,
    };
    var st_storage: [4][8]u8 = undefined;
    var cf_storage: [4][8]u8 = undefined;
    var vars: [8]Variable = undefined;
    var points: [4]ServerControlPoint = undefined;
    const st_items = [_][]const u8{
        "GGIO1$ST$SPCSO1$stVal", "GGIO1$ST$SPCSO2$stVal",
        "GGIO1$ST$SPCSO3$stVal", "GGIO1$ST$SPCSO4$stVal",
    };
    const cf_items = [_][]const u8{
        "GGIO1$CF$SPCSO1$ctlModel", "GGIO1$CF$SPCSO2$ctlModel",
        "GGIO1$CF$SPCSO3$ctlModel", "GGIO1$CF$SPCSO4$ctlModel",
    };
    const co_items = [_][]const u8{
        "GGIO1$CO$SPCSO1", "GGIO1$CO$SPCSO2", "GGIO1$CO$SPCSO3", "GGIO1$CO$SPCSO4",
    };
    for (0..4) |i| {
        var w = ber.Writer.init(&st_storage[i]);
        try Emit.boolean(&w, false);
        const d = w.done();
        std.mem.copyForwards(u8, st_storage[i][0..d.len], d);
        vars[i] = .{ .domain = ld, .item = st_items[i], .storage = &st_storage[i], .len = d.len };

        var cw = ber.Writer.init(&cf_storage[i]);
        // `ctlModel` is an enumerated integer on the wire.
        try Emit.integer(&cw, @intFromEnum(models[i]));
        const cd = cw.done();
        std.mem.copyForwards(u8, cf_storage[i][0..cd.len], cd);
        vars[4 + i] = .{ .domain = ld, .item = cf_items[i], .storage = &cf_storage[i], .len = cd.len };

        points[i] = .{
            .domain = ld,
            .item = co_items[i],
            .ctl_model = models[i],
            .sbo_timeout_ms = 30_000,
            .st_val = i,
        };
    }
    const domains = [_][]const u8{ld};
    var srv = Server.init(.{}, .{
        .variables = &vars,
        .controls = &points,
        .domains = &domains,
    });

    const peers = std.fmt.parseInt(usize, envVar("IEC61850_TEST_PEERS") orelse "1", 10) catch 1;
    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var notify: [4096]u8 = undefined;
    var served: usize = 0;
    var now: u64 = 0;
    while (served < peers) : (served += 1) {
        const stream = listener.accept(io) catch break;
        var tt = TcpTransport.fromStream(io, stream);
        tt.setReadTimeout(5000);
        const t = tt.transport();
        var rounds: usize = 0;
        while (rounds < 4000) : (rounds += 1) {
            const n = t.read(&in) catch break;
            if (n == 0) continue;
            now += 10;
            srv.tick(now);
            const reply = srv.handle(in[0..n], &out) catch continue;
            const rep = reply orelse break;
            t.write(rep) catch break;
            // A CommandTermination is not a response; it goes out on its own.
            while (srv.pendingNotification(&notify) catch null) |note| {
                t.write(note) catch break;
            }
        }
        tt.close();
    }
    if (served == 0) {
        if (verboseSkip()) std.debug.print("SKIPPED: live control server (no peer connected)\n", .{});
        return error.SkipZigTest;
    }
    var operated: usize = 0;
    for (0..4) |i| {
        if ((mmsdata.Data.decode(vars[i].value()) catch continue).boolean() catch continue) operated += 1;
    }
    std.debug.print(
        "live control server: peers={d} reads={d} writes={d} selects={d} operates={d} " ++
            "rejections={d} stVal_now={d}/4\n",
        .{ served, srv.reads, srv.writes, srv.selects, srv.operates, srv.control_rejections, operated },
    );
    try testing.expect(srv.operates > 0);
}

// Set IEC61850_TEST_LISTEN=host:port and point a real IEC 61850 client at it.
test "live: a real IEC 61850 client against our server" {
    const endpoint = envVar("IEC61850_TEST_LISTEN") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 server (set IEC61850_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 server (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live IEC 61850 server listening on {s}\n", .{endpoint});

    // A small but realistic model. The names are the ones a third-party
    // client's example browser reads, so an off-the-shelf IEC 61850 client can
    // drive this server without being told anything about it.
    var ind1: [8]u8 = undefined;
    var ind2: [8]u8 = undefined;
    var mag: [16]u8 = undefined;
    var vendor: [64]u8 = undefined;
    const ind1_len = try emitInto(&ind1, .{ .boolean = false });
    const ind2_len = try emitInto(&ind2, .{ .boolean = true });
    const mag_len = try emitInto(&mag, .{ .float = 42.5 });
    const vendor_len = try emitInto(&vendor, .{ .string = "zig-libs" });

    const ld = envVar("IEC61850_TEST_LISTEN_LD") orelse "simpleIOGenericIO";
    var vars = [_]Variable{
        .{ .domain = ld, .item = "GGIO1$ST$Ind1$stVal", .storage = &ind1, .len = ind1_len },
        .{ .domain = ld, .item = "GGIO1$ST$Ind2$stVal", .storage = &ind2, .len = ind2_len },
        .{ .domain = ld, .item = "GGIO1$MX$AnIn1$mag$f", .storage = &mag, .len = mag_len },
        .{ .domain = ld, .item = "GGIO1$DC$NamPlt$vendor", .storage = &vendor, .len = vendor_len, .writable = true },
    };
    const sets = [_]DataSet{.{ .domain = ld, .item = "LLN0$Events", .members = &[_]usize{ 0, 1 } }};
    const domains = [_][]const u8{ld};
    var srv = Server.init(.{}, .{ .variables = &vars, .data_sets = &sets, .domains = &domains });

    // Several clients in sequence, so more than one third-party tool can be
    // pointed at the same run.
    const peers = std.fmt.parseInt(usize, envVar("IEC61850_TEST_PEERS") orelse "1", 10) catch 1;
    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var served: usize = 0;
    while (served < peers) : (served += 1) {
        const stream = listener.accept(io) catch break;
        var tt = TcpTransport.fromStream(io, stream);
        tt.setReadTimeout(5000);
        const t = tt.transport();
        var rounds: usize = 0;
        while (rounds < 2000) : (rounds += 1) {
            const n = t.read(&in) catch break;
            if (n == 0) continue;
            const reply = srv.handle(in[0..n], &out) catch continue;
            const rep = reply orelse break;
            t.write(rep) catch break;
        }
        tt.close();
    }
    if (served == 0) {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 61850 server (no peer connected)\n", .{});
        return error.SkipZigTest;
    }
    std.debug.print(
        "live IEC 61850 server: peers={d} associated={} reads={d} writes={d} name_lists={d} vendor_now_len={d}\n",
        .{ served, srv.transport_up, srv.reads, srv.writes, srv.name_lists, vars[3].len },
    );
    // A third-party client that got as far as any MMS service proves the whole
    // COTP / session / presentation / ACSE / Initiate stack was accepted.
    try testing.expect(srv.reads + srv.writes + srv.name_lists > 0);
}

const Seed = union(enum) {
    boolean: bool,
    float: f32,
    string: []const u8,
};

/// Writes one `Data` value into the front of `buf` and returns its length.
fn emitInto(buf: []u8, seed: Seed) !usize {
    var w = ber.Writer.init(buf);
    switch (seed) {
        .boolean => |v| try Emit.boolean(&w, v),
        .float => |v| try Emit.float(&w, v),
        .string => |v| try Emit.visibleString(&w, v),
    }
    const d = w.done();
    const n = d.len;
    std.mem.copyForwards(u8, buf[0..n], d);
    return n;
}

// Set IEC61850_TEST_GOOSE_HEX=<file> to replay real GOOSE frames (one hex frame
// per line, as an AF_PACKET capture produces) through the subscriber state
// machine. Capturing the frames is the caller's job — see the note in
// `transport.zig` about wiring the sibling `rawsock` module.
test "live: real GOOSE frames through the subscriber" {
    const path = envVar("IEC61850_TEST_GOOSE_HEX") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live GOOSE replay (set IEC61850_TEST_GOOSE_HEX=<file>)\n", .{});
        return error.SkipZigTest;
    };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var text_buf: [1 << 20]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, path, &text_buf) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live GOOSE replay (cannot read {s})\n", .{path});
        return error.SkipZigTest;
    };

    var sub: ?Subscriber = null;
    var frames: usize = 0;
    var decoded: usize = 0;
    var state_changes: usize = 0;
    var gaps: usize = 0;
    var refreshes: usize = 0;
    var now: u64 = 0;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var buf: [2048]u8 = undefined;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len < 28 or trimmed.len % 2 != 0) continue;
        if (trimmed.len / 2 > buf.len) continue;
        var i: usize = 0;
        var ok = true;
        while (i * 2 < trimmed.len) : (i += 1) {
            buf[i] = std.fmt.parseInt(u8, trimmed[i * 2 ..][0..2], 16) catch {
                ok = false;
                break;
            };
        }
        if (!ok) continue;
        frames += 1;
        const f = GooseFrame.decode(buf[0 .. trimmed.len / 2]) catch continue;
        const p = GoosePdu.decode(f.pdu) catch continue;
        decoded += 1;
        if (sub == null) sub = Subscriber.init(.{ .gocb_ref = p.gocb_ref, .expected_conf_rev = p.conf_rev });
        if (!sub.?.matches(p)) continue;
        now += 100;
        const ev = sub.?.onFrame(p, now);
        if (ev.has(.state_change)) state_changes += 1;
        if (ev.has(.sequence_gap)) gaps += 1;
        if (ev.has(.refresh)) refreshes += 1;
    }
    std.debug.print(
        "live GOOSE replay: candidate_lines={d} decoded={d} refreshes={d} state_changes={d} gaps={d} usable={}\n",
        .{ frames, decoded, refreshes, state_changes, gaps, if (sub) |s| s.dataUsable() else false },
    );
    try testing.expect(decoded > 0);
}

// Set IEC61850_TEST_LISTEN_REPORT=host:port and point a real IEC 61850
// **reporting** or **log** client at it.
//
// The model deliberately carries the names the reference stack's own examples
// are hard-wired to: `simpleIOGenericIO/LLN0.RP.EventsRCB01` over
// `simpleIOGenericIO/LLN0$Events` for the reporting client, and
// `TestIEDGenericIO/LLN0$EventLog` for the log client — so an off-the-shelf
// client drives this server without being told anything about it.
//
// The loop is what makes reports possible at all: a short read timeout, and on
// every expiry the server's clock advances and whatever the reporting engine
// produced is pushed out unsolicited.
test "live: a real IEC 61850 client subscribing to reports from our server" {
    const endpoint = envVar("IEC61850_TEST_LISTEN_REPORT") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live reporting server (set IEC61850_TEST_LISTEN_REPORT=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live reporting server (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live reporting server listening on {s}\n", .{endpoint});

    const rpt_ld = "simpleIOGenericIO";
    const log_ld = "TestIEDGenericIO";

    var storage: [6][8]u8 = undefined;
    var vars: [6]Variable = undefined;
    const rpt_items = [_][]const u8{
        "GGIO1$ST$Ind1$stVal", "GGIO1$ST$Ind2$stVal",
        "GGIO1$ST$Ind3$stVal", "GGIO1$ST$Ind4$stVal",
    };
    for (0..4) |i| {
        vars[i] = .{
            .domain = rpt_ld,
            .item = rpt_items[i],
            .storage = &storage[i],
            .len = try emitInto(&storage[i], .{ .boolean = false }),
            .writable = true,
        };
    }
    for (4..6) |i| {
        vars[i] = .{
            .domain = log_ld,
            .item = rpt_items[i - 4],
            .storage = &storage[i],
            .len = try emitInto(&storage[i], .{ .boolean = false }),
            .writable = true,
        };
    }
    const sets = [_]DataSet{
        .{ .domain = rpt_ld, .item = "LLN0$Events", .members = &[_]usize{ 0, 1, 2, 3 } },
        .{ .domain = log_ld, .item = "LLN0$Events", .members = &[_]usize{ 4, 5 } },
    };

    const opt = OptFlds{
        .sequence_number = true,
        .report_time_stamp = true,
        .reason_for_inclusion = true,
        .data_set_name = true,
        .buffer_overflow = true,
        .conf_revision = true,
    };
    const trg = TrgOps{
        .data_change = true,
        .quality_change = true,
        .integrity = true,
        .general_interrogation = true,
    };
    var urcb_entries: [16]reporting.Entry = @splat(.{});
    var urcb_arena: [16 * 512]u8 = undefined;
    var brcb_entries: [16]reporting.Entry = @splat(.{});
    var brcb_arena: [16 * 512]u8 = undefined;
    var rcbs = [_]server.ReportControl{
        .{
            .kind = .unbuffered,
            .domain = rpt_ld,
            .item = "LLN0$RP$EventsRCB01",
            .rpt_id = "Events1",
            .dat_set = rpt_ld ++ "/LLN0$Events",
            .data_set = 0,
            .conf_rev = 1,
            .opt_flds = opt,
            .trg_ops = trg,
            .buf_tm_ms = 50,
            .intg_pd_ms = 1000,
            .buffer = try reporting.Buffer.init(&urcb_entries, &urcb_arena),
        },
        .{
            .kind = .buffered,
            .domain = rpt_ld,
            .item = "LLN0$BR$EventsBRCB01",
            .rpt_id = "Events2",
            .dat_set = rpt_ld ++ "/LLN0$Events",
            .data_set = 0,
            .conf_rev = 1,
            .opt_flds = opt,
            .trg_ops = trg,
            .buf_tm_ms = 50,
            .intg_pd_ms = 1000,
            .buffer = try reporting.Buffer.init(&brcb_entries, &brcb_arena),
        },
    };
    var log_entries: [16]logging.Entry = @splat(.{});
    var log_arena: [16 * 512]u8 = undefined;
    var logs = [_]server.LogControl{.{
        .domain = log_ld,
        .item = "LLN0$LG$EventLog",
        .journal = "LLN0$EventLog",
        .log_ref = log_ld ++ "/LLN0$EventLog",
        .dat_set = log_ld ++ "/LLN0$Events",
        .data_set = 1,
        .trg_ops = trg,
        .store = try logging.Store.init(&log_entries, &log_arena),
        // A configured IED logs from the moment it starts; a client that writes
        // `LogEna` is turning it *off* and on again, not switching it on.
        .log_ena = true,
    }};

    var set_store: [4 * 16]u8 = undefined;
    var set_lens: [4]usize = @splat(0);
    var settings = [_]settinggroups.Setting{.{
        .domain = rpt_ld,
        .ln = "PTOC1",
        .path = "StrVal$setMag$f",
        .storage = &set_store,
        .lens = &set_lens,
    }};
    for (0..4) |g| {
        var tmp: [16]u8 = undefined;
        var w = ber.Writer.init(&tmp);
        try Emit.float(&w, @floatFromInt(g + 1));
        const d = w.done();
        @memcpy(set_store[g * 16 ..][0..d.len], d);
        set_lens[g] = d.len;
    }
    var sgcb = server.SettingGroups{ .domain = rpt_ld, .groups = 3, .settings = &settings };
    try sgcb.validate();

    const domains = [_][]const u8{ rpt_ld, log_ld };
    var srv = Server.init(.{}, .{
        .variables = &vars,
        .data_sets = &sets,
        .report_controls = &rcbs,
        .logs = &logs,
        .setting_groups = &sgcb,
        .domains = &domains,
    });

    const peers = std.fmt.parseInt(usize, envVar("IEC61850_TEST_PEERS") orelse "1", 10) catch 1;
    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var notify: [16384]u8 = undefined;
    var served: usize = 0;
    // A plausible wall clock, so a third-party client prints a sensible
    // `TimeOfEntry` — the module still owns no clock; this is the caller's.
    var now: u64 = 1_700_000_000_000;
    var next_toggle: u64 = now + 400;
    var toggles: usize = 0;
    while (served < peers) : (served += 1) {
        const stream = listener.accept(io) catch break;
        var tt = TcpTransport.fromStream(io, stream);
        // Short, so an idle connection still lets the clock move.
        tt.setReadTimeout(200);
        const t = tt.transport();
        var idle: usize = 0;
        var rounds: usize = 0;
        while (rounds < 20000 and idle < 150) : (rounds += 1) {
            // A read timeout comes back as **zero bytes**, not as an error, so
            // both have to land on the idle path — otherwise the clock never
            // moves and no report is ever produced on the server's own
            // schedule.
            const n = t.read(&in) catch 0;
            if (n == 0) {
                // The read timed out: advance the IED's clock, flip a status
                // point if enough of it has passed, and push whatever that
                // produced. The process runs on its own schedule, not on the
                // client's — which is the entire point of a report.
                idle += 1;
                now += 200;
                if (now >= next_toggle) {
                    next_toggle = now + 400;
                    const which = toggles % 4;
                    const value = (toggles / 4) % 2 == 0;
                    vars[which].len = emitInto(&storage[which], .{ .boolean = value }) catch 0;
                    srv.signal(which, .data_change);
                    vars[4 + (which % 2)].len =
                        emitInto(&storage[4 + (which % 2)], .{ .boolean = value }) catch 0;
                    srv.signal(4 + (which % 2), .data_change);
                    toggles += 1;
                }
                srv.tick(now);
                while (srv.pendingNotification(&notify) catch null) |note| {
                    t.write(note) catch break;
                }
                continue;
            }
            idle = 0;
            now += 10;
            srv.tick(now);
            const reply = srv.handle(in[0..n], &out) catch continue;
            const rep = reply orelse break;
            t.write(rep) catch break;
            while (srv.pendingNotification(&notify) catch null) |note| {
                t.write(note) catch break;
            }
        }
        srv.releaseAssociation();
        tt.close();
    }
    if (served == 0) {
        if (verboseSkip()) std.debug.print("SKIPPED: live reporting server (no peer connected)\n", .{});
        return error.SkipZigTest;
    }
    std.debug.print(
        "live reporting server: peers={d} reads={d} writes={d} reports_sent={d} " ++
            "journal_reads={d} urcb_reports={d} brcb_reports={d} log_entries={d} sg_confirms={d}\n",
        .{
            served,                  srv.reads,               srv.writes,
            srv.reports_sent,        srv.journal_reads,       rcbs[0].reports_emitted,
            rcbs[1].reports_emitted, logs[0].entries_written, sgcb.confirmations,
        },
    );
    try testing.expect(srv.reads + srv.writes > 0);
}

// Set IEC61850_TEST_SCL_FILE=<path> to run the **emission** round trip over a
// real configuration file: parse it, serialise the model back to SCL, parse the
// emission and assert the two resolved name spaces are identical, name for
// name. IEC61850_TEST_SCL_IED picks the IED (default: the only one);
// IEC61850_TEST_SCL_OUT, when set, writes the emitted document there so a
// third-party tool can be pointed at it.
test "live: an SCL file survives parse → emit → parse with an identical name space" {
    const path = envVar("IEC61850_TEST_SCL_FILE") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL emission (set IEC61850_TEST_SCL_FILE=<path>)\n", .{});
        return error.SkipZigTest;
    };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const source = std.Io.Dir.cwd().readFileAlloc(io, path, testing.allocator, .unlimited) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL emission (cannot read {s})\n", .{path});
        return error.SkipZigTest;
    };
    defer testing.allocator.free(source);

    var a = scl.parse(testing.allocator, source, .{ .allow_unknown_btype = true, .check_values = false }) catch |e| {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL emission ({s} does not parse: {t})\n", .{ path, e });
        return error.SkipZigTest;
    };
    defer a.deinit();
    if (a.ieds.len == 0) {
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL emission ({s} has no IED)\n", .{path});
        return error.SkipZigTest;
    }
    const ied_name = envVar("IEC61850_TEST_SCL_IED") orelse a.ieds[0].name;

    var model_a = scl.resolve(&a, testing.allocator, ied_name) catch |e| {
        // The *source* does not resolve — an `.scd` whose data sets reach into
        // another IED, most often. Nothing to say about the emitter here.
        if (verboseSkip()) std.debug.print("SKIPPED: live SCL emission ({s} does not resolve: {t})\n", .{ path, e });
        return error.SkipZigTest;
    };
    defer model_a.deinit();

    const emitted = try sclwrite.emitParsed(testing.allocator, &a, .{ .allow_lossy = true });
    defer testing.allocator.free(emitted);
    if (envVar("IEC61850_TEST_SCL_OUT")) |out_path| {
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = emitted }) catch {};
    }

    var b = try scl.parse(testing.allocator, emitted, .{ .allow_unknown_btype = true, .check_values = false });
    defer b.deinit();
    var model_b = try scl.resolve(&b, testing.allocator, ied_name);
    defer model_b.deinit();

    // Compared as a **set**: the emitter puts `LN0` first because the schema
    // sequences it there, and plenty of real files do not.
    try testing.expectEqual(model_a.nodes.len, model_b.nodes.len);
    var mismatches: usize = 0;
    for (model_a.nodes) |x| {
        const y = model_b.find(x.domain, x.item) orelse {
            mismatches += 1;
            continue;
        };
        if (x.fc != y.fc or x.b_type != y.b_type or x.leaf != y.leaf) mismatches += 1;
    }
    std.debug.print(
        "live SCL emission: {s} ied={s} names={d} emitted={d} bytes mismatches={d}\n",
        .{ path, ied_name, model_a.nodes.len, emitted.len, mismatches },
    );
    try testing.expectEqual(@as(usize, 0), mismatches);
    try testing.expect(model_a.nodes.len > 0);
}

// Set IEC61850_TEST_LISTEN_SEGMENT=host:port and point a real IEC 61850
// **reporting** client at it.
//
// The model is deliberately *wide*: `simpleIOGenericIO/LLN0$Events` carries
// twelve members of ~700 octets each, so one report is far larger than the
// negotiated MMS PDU and the server has to split it. The RCB is the one the
// reference stack's own reporting example is hard-wired to
// (`simpleIOGenericIO/LLN0.RP.EventsRCB01`), so an off-the-shelf client drives
// the segmented path without being told anything about it — and the proof is
// that it prints **all twelve members of one report**, which it can only do by
// reassembling.
test "live: a real IEC 61850 client reassembling a segmented report from our server" {
    const endpoint = envVar("IEC61850_TEST_LISTEN_SEGMENT") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live segmented reporting (set IEC61850_TEST_LISTEN_SEGMENT=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live segmented reporting (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live segmented reporting listening on {s}\n", .{endpoint});

    const ld = "simpleIOGenericIO";
    const members = 12;
    const payload = 660;

    var storage: [members][payload + 8]u8 = undefined;
    var names: [members][32]u8 = undefined;
    var vars: [members]Variable = undefined;
    for (0..members) |i| {
        var body: [payload]u8 = undefined;
        for (0..payload) |k| body[k] = @intCast((i * 31 + k) & 0x7F | 0x20);
        var w = ber.Writer.init(&storage[i]);
        try Emit.visibleString(&w, &body);
        const d = w.done();
        std.mem.copyForwards(u8, storage[i][0..d.len], d);
        vars[i] = .{
            .domain = ld,
            .item = try std.fmt.bufPrint(&names[i], "GGIO1$ST$Ind{d}$stVal", .{i + 1}),
            .storage = &storage[i],
            .len = d.len,
            .writable = true,
        };
    }
    var indices: [members]usize = undefined;
    for (0..members) |i| indices[i] = i;
    const sets = [_]DataSet{.{ .domain = ld, .item = "LLN0$Events", .members = &indices }};

    var entries: [4]reporting.Entry = @splat(.{});
    var arena: [4 * (members * (payload + 16))]u8 = undefined;
    var rcbs = [_]server.ReportControl{.{
        .kind = .unbuffered,
        .domain = ld,
        .item = "LLN0$RP$EventsRCB01",
        .rpt_id = "Events1",
        .dat_set = ld ++ "/LLN0$Events",
        .data_set = 0,
        .conf_rev = 1,
        .opt_flds = .{
            .sequence_number = true,
            .report_time_stamp = true,
            .reason_for_inclusion = true,
            .data_set_name = true,
            .conf_revision = true,
            // `data_reference` is what makes the *report* larger than a plain
            // read of the same data set: the read carries only the values, the
            // report carries each member's object reference as well. A COTP
            // class-0 TPDU can never exceed 8192 octets and this module does
            // not split one PDU across several TPDUs, so that gap is exactly
            // where a report has to segment and a read still fits.
            .data_reference = true,
            // The whole point of this run.
            .segmentation = true,
        },
        .trg_ops = .{
            .data_change = true,
            .quality_change = true,
            .integrity = true,
            .general_interrogation = true,
        },
        .buf_tm_ms = 50,
        .intg_pd_ms = 2000,
        .buffer = try reporting.Buffer.init(&entries, &arena),
    }};

    const domains = [_][]const u8{ld};
    var srv = Server.init(.{}, .{
        .variables = &vars,
        .data_sets = &sets,
        .report_controls = &rcbs,
        .domains = &domains,
    });

    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var notify: [32768]u8 = undefined;
    var now: u64 = 1_700_000_000_000;
    var served: usize = 0;
    const peers = std.fmt.parseInt(usize, envVar("IEC61850_TEST_PEERS") orelse "1", 10) catch 1;
    var segments_sent: u64 = 0;
    // How many PDUs went out that were *not* the last segment of their report:
    // non-zero is the whole claim.
    var split_reports: u64 = 0;
    while (served < peers) : (served += 1) {
        const stream = listener.accept(io) catch break;
        var tt = TcpTransport.fromStream(io, stream);
        tt.setReadTimeout(200);
        const t = tt.transport();
        var idle: usize = 0;
        var rounds: usize = 0;
        var toggles: usize = 0;
        while (rounds < 20000 and idle < 100) : (rounds += 1) {
            const n = t.read(&in) catch 0;
            if (n == 0) {
                idle += 1;
                now += 200;
                if (toggles < 4) {
                    const which = toggles % members;
                    var body: [payload]u8 = undefined;
                    for (0..payload) |k| body[k] = @intCast((toggles * 7 + k) & 0x3F | 0x40);
                    var w = ber.Writer.init(&storage[which]);
                    Emit.visibleString(&w, &body) catch {};
                    const d = w.done();
                    std.mem.copyForwards(u8, storage[which][0..d.len], d);
                    vars[which].len = d.len;
                    srv.signal(which, .data_change);
                    toggles += 1;
                }
                srv.tick(now);
                while (srv.pendingNotification(&notify) catch null) |note| {
                    segments_sent += 1;
                    if (rcbs[0].segmenting()) split_reports += 1;
                    t.write(note) catch break;
                }
                continue;
            }
            idle = 0;
            now += 10;
            srv.tick(now);
            const reply = srv.handle(in[0..n], &out) catch continue;
            const rep = reply orelse break;
            t.write(rep) catch break;
            while (srv.pendingNotification(&notify) catch null) |note| {
                segments_sent += 1;
                if (rcbs[0].segmenting()) split_reports += 1;
                t.write(note) catch break;
            }
        }
        srv.releaseAssociation();
        tt.close();
    }
    if (served == 0) {
        if (verboseSkip()) std.debug.print("SKIPPED: live segmented reporting (no peer connected)\n", .{});
        return error.SkipZigTest;
    }
    std.debug.print(
        "live segmented reporting: peers={d} negotiated_pdu={d} negotiated_tpdu={d} budget={d} " ++
            "members={d} member_bytes={d} segments_sent={d} split_reports={d} sq_num={d}\n",
        .{
            served,                    srv.negotiated_pdu_len, srv.negotiated_tpdu_len,
            srv.reportSegmentBudget(), members,                payload,
            segments_sent,             split_reports,          rcbs[0].sq_num,
        },
    );
    // At least one report went out in more than one PDU.
    try testing.expect(split_reports > 0);
    try testing.expect(srv.reads + srv.writes > 0);
}

// Set IEC61850_TEST_LISTEN_RESV=host:port and point **two** IEC 61850 reporting
// clients at it at the same time.
//
// Both are hard-wired to `simpleIOGenericIO/LLN0.RP.EventsRCB01`, so they
// contend for one report control block. The first to write `RptEna` owns it;
// the second's write is refused with `object-access-denied` and its own stack
// reports the failure. `Owner` names the winner in the four octets of its
// association id.
//
// The two associations are multiplexed onto one `Server` by round-robin, with
// `Server.peer` set to the socket's id before every frame — which is exactly
// the seam a production front end uses. One caveat, stated rather than hidden:
// the presentation-context table is shared, which works only because both
// peers propose the same context ids. A real front end gives each association
// its own.
test "live: two real IEC 61850 clients contending for one report control block" {
    const endpoint = envVar("IEC61850_TEST_LISTEN_RESV") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live RCB reservation (set IEC61850_TEST_LISTEN_RESV=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live RCB reservation (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live RCB reservation listening on {s}\n", .{endpoint});

    const ld = "simpleIOGenericIO";
    var storage: [4][8]u8 = undefined;
    var vars: [4]Variable = undefined;
    const items = [_][]const u8{
        "GGIO1$ST$Ind1$stVal", "GGIO1$ST$Ind2$stVal",
        "GGIO1$ST$Ind3$stVal", "GGIO1$ST$Ind4$stVal",
    };
    for (0..4) |i| {
        vars[i] = .{
            .domain = ld,
            .item = items[i],
            .storage = &storage[i],
            .len = try emitInto(&storage[i], .{ .boolean = false }),
            .writable = true,
        };
    }
    const sets = [_]DataSet{.{ .domain = ld, .item = "LLN0$Events", .members = &[_]usize{ 0, 1, 2, 3 } }};
    var entries: [16]reporting.Entry = @splat(.{});
    var arena: [16 * 256]u8 = undefined;
    var rcbs = [_]server.ReportControl{.{
        .kind = .unbuffered,
        .domain = ld,
        .item = "LLN0$RP$EventsRCB01",
        .rpt_id = "Events1",
        .dat_set = ld ++ "/LLN0$Events",
        .data_set = 0,
        .conf_rev = 1,
        .opt_flds = .{
            .sequence_number = true,
            .report_time_stamp = true,
            .reason_for_inclusion = true,
            .data_set_name = true,
            .conf_revision = true,
        },
        .trg_ops = .{ .data_change = true, .general_interrogation = true },
        .buf_tm_ms = 50,
        // `Owner` is a member of the structure here, so a browsing client sees
        // who holds the block without asking for the attribute by name.
        .include_owner = true,
        .buffer = try reporting.Buffer.init(&entries, &arena),
    }};
    const domains = [_][]const u8{ld};
    var srv = Server.init(.{}, .{
        .variables = &vars,
        .data_sets = &sets,
        .report_controls = &rcbs,
        .domains = &domains,
    });

    // Two associations, accepted up front. `accept` blocks, so the second
    // client has to be started within the driver's window; that is the
    // script's job, not this loop's.
    const max_links: usize = 4;
    const want = @min(
        max_links,
        std.fmt.parseInt(usize, envVar("IEC61850_TEST_PEERS") orelse "2", 10) catch 2,
    );
    var links: [max_links]TcpTransport = undefined;
    var live: [max_links]bool = @splat(false);
    var accepted: usize = 0;
    // The first peer is waited for; the rest are picked up **between passes**,
    // so an early client is served while a later one is still connecting. A
    // blocking accept would starve whoever got in first.
    {
        const stream = listener.accept(io) catch {
            if (verboseSkip()) std.debug.print("SKIPPED: live RCB reservation (no peer connected)\n", .{});
            return error.SkipZigTest;
        };
        links[0] = TcpTransport.fromStream(io, stream);
        links[0].setReadTimeout(100);
        live[0] = true;
        accepted = 1;
    }

    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var notify: [16384]u8 = undefined;
    var now: u64 = 1_700_000_000_000;
    var idle: usize = 0;
    var rounds: usize = 0;
    var refusals: usize = 0;
    var first_owner: ?u32 = null;
    var owner_changes: usize = 0;
    while (rounds < 40000 and idle < 200) : (rounds += 1) {
        // Pick up a peer that has arrived since the last pass.
        if (accepted < want and listenerReadable(listener.socket.handle)) {
            if (listener.accept(io)) |stream| {
                links[accepted] = TcpTransport.fromStream(io, stream);
                links[accepted].setReadTimeout(100);
                live[accepted] = true;
                accepted += 1;
            } else |_| {}
        }
        var any = false;
        for (0..accepted) |i| {
            if (!live[i]) continue;
            // The association a frame arrived on is what owns the block.
            srv.peer = 0xC0A8_0100 + @as(u32, @intCast(i)) + 1;
            const t = links[i].transport();
            const n = t.read(&in) catch 0;
            if (n == 0) continue;
            any = true;
            now += 10;
            srv.tick(now);
            const before = srv.writes;
            const reply = srv.handle(in[0..n], &out) catch continue;
            const rep = reply orelse {
                srv.releaseAssociationOf(srv.peer);
                links[i].close();
                live[i] = false;
                continue;
            };
            t.write(rep) catch {};
            if (srv.writes > before and rcbs[0].owner != null and rcbs[0].owner.? != srv.peer) {
                refusals += 1;
            }
            if (rcbs[0].owner) |o| {
                if (first_owner == null) first_owner = o;
                if (first_owner.? != o) owner_changes += 1;
            }
            while (srv.pendingNotification(&notify) catch null) |note| {
                t.write(note) catch break;
            }
        }
        if (!any) {
            idle += 1;
            now += 100;
            srv.tick(now);
            for (0..accepted) |i| {
                if (!live[i]) continue;
                srv.peer = 0xC0A8_0100 + @as(u32, @intCast(i)) + 1;
                const t = links[i].transport();
                while (srv.pendingNotification(&notify) catch null) |note| {
                    t.write(note) catch break;
                }
            }
            var all_gone = true;
            for (0..accepted) |i| {
                if (live[i]) all_gone = false;
            }
            if (all_gone) break;
        } else idle = 0;
    }
    for (0..accepted) |i| {
        if (live[i]) {
            srv.releaseAssociationOf(0xC0A8_0100 + @as(u32, @intCast(i)) + 1);
            links[i].close();
        }
    }
    std.debug.print(
        "live RCB reservation: peers={d} reads={d} writes={d} refused_writes={d} " ++
            "first_owner=0x{X} owner_changes={d} reports={d}\n",
        .{
            accepted,             srv.reads,     srv.writes,              refusals,
            first_owner orelse 0, owner_changes, rcbs[0].reports_emitted,
        },
    );
    try testing.expect(srv.reads + srv.writes > 0);
    try testing.expect(first_owner != null);
}

/// Whether a listening socket has a connection waiting, without blocking.
fn listenerReadable(handle: std.posix.fd_t) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, 0) catch return false;
    return n != 0;
}
