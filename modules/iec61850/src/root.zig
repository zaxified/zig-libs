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

pub const meta = .{
    // Codecs, state machines, client PDU logic and the responder are pure
    // computation; only the optional TcpTransport touches std.Io.net.
    .platform = .any,
    .role = .both, // client + server, publisher + subscriber
    // One Client/Server owns one association's buffers and invoke ids; one
    // Publisher/Subscriber owns one control block's counters. Nothing shared,
    // no clock, no thread — those are the caller's.
    .concurrency = .single_owner,
    .model_after = "ISO 9506 (MMS) as profiled by IEC 61850-8-1, over ISO 8073/8327/8823/8650; wire behaviour cross-checked against captured traffic between two independent third-party stacks and against the Wireshark mms/goose dissectors (see SPEC.md)",
    .deps = .{},
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

// ── top-level names (the ones a consumer actually types) ────────────────────

pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const ReportHandler = client.ReportHandler;

pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const Model = server.Model;
pub const Variable = server.Variable;
pub const DataSet = server.DataSet;

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

pub const Rcb = report.Rcb;
pub const Report = report.Report;
pub const OptFlds = report.OptFlds;
pub const TrgOps = report.TrgOps;

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
    _ = goose;
    _ = publisher;
    _ = subscriber;
    _ = sv;
    _ = transport;
    _ = client;
    _ = server;
    _ = goldens;
}

// ── tests: the whole stack, client against server ──────────────────────────

const testing = std.testing;

test "meta names no sibling dependencies" {
    try testing.expectEqual(@as(usize, 0), meta.deps.len);
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

// ── live interop ────────────────────────────────────────────────────────────
//
// All three print `SKIPPED: …` and pass when no peer is present.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

const Endpoint = struct { host: []const u8, port: u16 };

fn splitEndpoint(endpoint: []const u8) ?Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;
    return .{ .host = endpoint[0..colon], .port = port };
}

var live_reports: usize = 0;
var live_report_entries: usize = 0;

fn onLiveReport(_: *anyopaque, r: Report) void {
    live_reports += 1;
    live_report_entries += r.entry_count;
}

// Set IEC61850_TEST_SERVER=host:port to run a real round trip against a live
// IEC 61850 server. IEC61850_TEST_LD names the logical device to browse
// (default `simpleIOGenericIO`).
test "live: our client against a real IEC 61850 server" {
    const endpoint = envVar("IEC61850_TEST_SERVER") orelse {
        std.debug.print("SKIPPED: live IEC 61850 client (set IEC61850_TEST_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const ld = envVar("IEC61850_TEST_LD") orelse "simpleIOGenericIO";

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        std.debug.print("SKIPPED: live IEC 61850 client (cannot connect to {s})\n", .{endpoint});
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

// Set IEC61850_TEST_LISTEN=host:port and point a real IEC 61850 client at it.
test "live: a real IEC 61850 client against our server" {
    const endpoint = envVar("IEC61850_TEST_LISTEN") orelse {
        std.debug.print("SKIPPED: live IEC 61850 server (set IEC61850_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        std.debug.print("SKIPPED: live IEC 61850 server (cannot bind {s})\n", .{endpoint});
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
        std.debug.print("SKIPPED: live IEC 61850 server (no peer connected)\n", .{});
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
        std.debug.print("SKIPPED: live GOOSE replay (set IEC61850_TEST_GOOSE_HEX=<file>)\n", .{});
        return error.SkipZigTest;
    };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var text_buf: [1 << 20]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, path, &text_buf) catch {
        std.debug.print("SKIPPED: live GOOSE replay (cannot read {s})\n", .{path});
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
