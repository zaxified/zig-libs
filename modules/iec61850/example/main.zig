// SPDX-License-Identifier: MIT

//! What a station-bus consumer does with `iec61850`: take the raw Ethernet
//! frames a GOOSE publisher multicasts, decide whether they may be acted on,
//! and read the data set out of them.
//!
//! The interesting part is not the decode — it is the four conditions the
//! subscriber distinguishes. A protection scheme that conflates "the data
//! changed" with "frames were lost" with "the publisher's data set was
//! reconfigured" either flaps or acts on values that no longer mean what its
//! configuration says. So this example handles a `confRev` change explicitly:
//! the bytes still parse perfectly, and that is exactly what makes it
//! dangerous.
//!
//! No socket and no clock: frames come in as byte slices, and time is a `u64`
//! the caller supplies. That is what lets a downstream project replay a
//! capture through the real state machine.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const iec = @import("iec61850");

fn unhex(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(20_000);
    var out: [hex.len / 2]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
    return out;
}

/// One GOOSE frame off the process bus: destination is the IEC 61850
/// multicast group, APPID 1000, `stNum` 1 / `sqNum` 0, `confRev` 3, and three
/// data-set entries.
const frame_1 = unhex(
    "010ccd010001" ++ "020000000001" ++ "88b8" ++
        "03e8" ++ "00b8" ++ "0000" ++ "0000" ++
        "6181ad" ++
        "8029" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
        "810201f4" ++
        "8223" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024416e616c6f6756616c756573" ++
        "8329" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
        "84086a61d98fc418930a" ++
        "850101" ++ "860100" ++ "870100" ++ "880101" ++ "890100" ++ "8a0103" ++
        "ab10" ++ "850204d2" ++ "8c06000000000000" ++ "8502162e",
);

/// The same publisher a moment later. Two things changed at once: `sqNum`
/// jumped 0 → 3 (two retransmissions never arrived) and `confRev` went 3 → 4
/// with a fourth entry appended to the data set.
const frame_2 = unhex(
    "010ccd010001" ++ "020000000001" ++ "88b8" ++
        "03e8" ++ "00bb" ++ "0000" ++ "0000" ++
        "6181b0" ++
        "8029" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
        "810201f4" ++
        "8223" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024416e616c6f6756616c756573" ++
        "8329" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
        "84086a61d98fc418930a" ++
        "850101" ++ "860103" ++ "870100" ++ "880101" ++ "890100" ++ "8a0104" ++
        "ab13" ++ "850204d2" ++ "8c06000000000000" ++ "8502162e" ++ "830101",
);

const gocb_ref = "simpleIOGenericIO/LLN0$GO$gcbAnalogValues";

/// The subscriber tells the caller what happened; deciding what that means for
/// the plant is the caller's job, and each of these is a different decision.
fn describe(ev: iec.Event) void {
    switch (ev) {
        .first => |f| std.debug.print("  publisher seen, stNum={d} sqNum={d}\n", .{ f.st_num, f.sq_num }),
        .refresh => std.debug.print("  retransmission, nothing changed\n", .{}),
        .state_change => |s| std.debug.print("  DATA CHANGED stNum {d} -> {d}\n", .{ s.previous, s.st_num }),
        .sequence_gap => |g| std.debug.print("  LOST FRAMES: expected sqNum {d}, got {d}\n", .{ g.expected, g.got }),
        .tal_expired => |t| std.debug.print("  PUBLISHER DEAD: silent past its {d} ms TAL\n", .{t.tal_ms}),
        .conf_rev_mismatch => |c| std.debug.print("  CONFIG DRIFT: confRev {d}, configured for {d}\n", .{ c.got, c.expected }),
        .out_of_order => |o| std.debug.print("  reordered or duplicate frame stNum={d} sqNum={d}\n", .{ o.st_num, o.sq_num }),
        .test_frame => std.debug.print("  test frame: must not operate anything\n", .{}),
        .needs_commissioning => std.debug.print("  ndsCom set: publisher says its config is incomplete\n", .{}),
        .recovered => |r| std.debug.print("  publisher back after {d} ms\n", .{r.down_for_ms}),
    }
}

/// Reads the analogue values out of `allData`. The data set is a flat list of
/// MMS `Data` values whose types come from the SCL, so a subscriber that was
/// configured against a different `confRev` is reading the wrong columns —
/// which is why the caller must check that first.
fn printValues(pdu: iec.GoosePdu) !void {
    var members = pdu.values();
    var i: usize = 0;
    while (try members.next()) |d| : (i += 1) {
        std.debug.print("  [{d}] {s} = ", .{ i, @tagName(d.kind) });
        switch (d.kind) {
            .integer, .unsigned, .floating_point => std.debug.print("{d}\n", .{try d.asFloat()}),
            .boolean => std.debug.print("{}\n", .{try d.boolean()}),
            .binary_time => std.debug.print("(timestamp)\n", .{}),
            else => std.debug.print("({d} octets)\n", .{d.content.len}),
        }
    }
}

pub fn main() !void {
    // Bound to one control block and one dataset revision. A discovery tool
    // would leave `expected_conf_rev` null; a protection scheme must not.
    var sub = iec.Subscriber.init(.{
        .gocb_ref = gocb_ref,
        .expected_conf_rev = 3,
    });

    for ([_][]const u8{ &frame_1, &frame_2 }, [_]u64{ 1_000, 1_050 }) |bytes, now_ms| {
        const frame = iec.goose.Frame.decode(bytes) catch |err| switch (err) {
            // Everything on a process-bus port that is not GOOSE — the sniffer
            // hands it over and the subscriber declines it. Not a fault.
            error.NotGoose => continue,
            // A truncated capture or a publisher whose Length field lies.
            error.ShortFrame, error.LengthMismatch => {
                std.debug.print("malformed frame, dropping\n", .{});
                continue;
            },
            else => return err,
        };

        if (!iec.goose.isGooseMulticast(frame.dst)) {
            std.debug.print("GOOSE sent to a unicast address, ignoring\n", .{});
            continue;
        }

        const pdu = iec.goose.Pdu.decode(frame.pdu) catch |err| switch (err) {
            // The publisher's own count of data-set entries disagrees with
            // what it sent: the frame is internally inconsistent and no part
            // of it can be trusted.
            error.EntryCountMismatch, error.MissingField => {
                std.debug.print("inconsistent GOOSE PDU, dropping\n", .{});
                continue;
            },
            // The same context tag twice. Left last-wins, a subscriber and an
            // IDS watching the same wire would disagree about stNum.
            error.DuplicateField => {
                std.debug.print("duplicate field in GOOSE PDU, dropping\n", .{});
                continue;
            },
            else => return err,
        };

        // Frames from other control blocks share the multicast group.
        if (!sub.matches(pdu)) continue;

        std.debug.print("appid={d} t={d}s stNum={d} sqNum={d}\n", .{
            frame.appid,
            pdu.t.seconds,
            pdu.st_num,
            pdu.sq_num,
        });

        const events = sub.onFrame(pdu, now_ms);
        for (events.slice()) |ev| describe(ev);

        // One frame can carry several conditions at once, and the ordering
        // between them matters: a confRev mismatch means the values decode
        // fine but no longer map to the configured signals, so it is checked
        // before anything reads them.
        if (events.has(.conf_rev_mismatch)) {
            std.debug.print("  -> not reading values until the config is refreshed\n", .{});
            continue;
        }
        try printValues(pdu);
    }

    // Liveness is the caller's loop, driven by `nextDeadline`. Nothing here
    // owns a timer.
    if (sub.nextDeadline()) |deadline| {
        std.debug.print("next liveness check at {d} ms\n", .{deadline});
        if (sub.tick(deadline)) |ev| describe(ev);
    }
    std.debug.print("data usable: {}\n", .{sub.dataUsable()});
}
