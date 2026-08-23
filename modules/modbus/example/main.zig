// SPDX-License-Identifier: MIT

//! `modbus-demo` — one binary, two modes (`server` and `client`) that talk to
//! each other over a **real Modbus TCP socket**. Run the server in one
//! terminal, the client in another, and watch a SCADA master drive a field
//! device. Either half can equally be pointed at a foreign implementation:
//! the client at any Modbus TCP slave, the server at any Modbus TCP master.
//!
//! **The thing worth reading this for is that Modbus has FOUR data areas, and
//! confusing them is the mistake every newcomer makes.** Coils (FC 01) and
//! discrete inputs (FC 02) are single bits; holding registers (FC 03) and
//! input registers (FC 04) are 16-bit words. Address 0 exists in all four and
//! means four different things — the "0" in `readCoils(unit, 0, ...)` and the
//! "0" in `readInputRegisters(unit, 0, ...)` are not the same point. So this
//! demo populates all four with values that name their own area, reads all
//! four, and writes to one of each writable kind. `server.DataBank` is already
//! exactly the pokeable register map that needs: four windows, each with its
//! own base address and its own storage, all caller-owned.
//!
//! **The server's accept loop is example code, and that is deliberate.** The
//! module ships `handleAdu(request, out) -> ?[]u8` as a pure function and
//! stops there — no threads, no sockets, no allocation — which is what makes
//! it drivable from a fuzz harness, a fleet simulator, or a gateway. The
//! twenty lines that turn it into a daemon are below, and a reader who needs
//! a different concurrency model writes their own twenty.
//!
//! **TCP framing (MBAP), not RTU.** Both are implemented on both sides, but
//! RTU wants a real serial line with t3.5 inter-frame silence; a demo you
//! cannot run without a USB-485 dongle is not a demo. Everything the reader
//! sees here is framing-independent — swap `.tcp` for `.rtu` on both `init`
//! calls and the same conversation runs over a serial port.
//!
//! **The client is honestly incomplete, and shows it.** The `Server` answers
//! three function codes the `Client` has no typed method for: 0x07 Read
//! Exception Status, 0x08 Diagnostics, 0x11 Report Slave ID. `rawExchange`
//! below builds those PDUs by hand and reuses the module's framing, which is
//! what the module's own doc comment tells a caller to do — see the ⚠ note on
//! that function for how far the module actually helps.
//!
//! Built against the PUBLISHED module (`@import("modbus")`) only — no
//! `test_deps`, no reaching into `src/`. If a type needed to call this API is
//! not public, or an error cannot be named from outside, this file stops
//! compiling; the module's own tests cannot notice either, because they live
//! inside it.

const std = @import("std");
const modbus = @import("modbus");

/// Anything that is this demo's own failure rather than the protocol saying
/// no. A Modbus exception is a successful conversation with an unwelcome
/// answer, and exits 0.
const local_failure_exit: u8 = 1;

/// Not 502. The standard Modbus TCP port is privileged, and a demo that needs
/// root to bind teaches the wrong first lesson. 5020 is the conventional
/// unprivileged stand-in.
const default_port: u16 = 5020;

const usage_text =
    \\modbus-demo — a Modbus TCP master/slave demo for the `modbus` module.
    \\
    \\usage:
    \\  modbus-demo server [options]
    \\  modbus-demo client [options]
    \\
    \\server options:
    \\  --listen <addr>    address to bind                (default 127.0.0.1)
    \\  --port <port>      TCP port                       (default 5020)
    \\  --unit <id>        unit id this slave answers for (default 1)
    \\  --any-unit         answer for EVERY unit id (gateway mode); off by
    \\                     default, because a simulator that answers for
    \\                     addresses it was not given teaches the wrong lesson
    \\  --once             serve one connection, then exit
    \\  -h, --help         this text
    \\
    \\client options:
    \\  --host <host>      slave to connect to            (default 127.0.0.1)
    \\  --port <port>      TCP port                       (default 5020)
    \\  --unit <id>        unit id to address             (default 1)
    \\  --silent-probe     finish by addressing a unit id the slave does not
    \\                     answer for. A real slave stays SILENT for that (it
    \\                     is not an error on the wire), and this client then
    \\                     blocks forever — see the ⚠ note at `silentProbe`.
    \\  -h, --help         this text
    \\
    \\Two terminals:
    \\  modbus-demo server --once
    \\  modbus-demo client
    \\
    \\Against a foreign implementation (pymodbus is the one this module's
    \\goldens were captured from):
    \\  python3 -c "from pymodbus.client import ModbusTcpClient as C; c=C('127.0.0.1',port=5020); c.connect(); print(c.read_holding_registers(0,count=8,device_id=1).registers)"
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract (CONVENTIONS.md §7.2). `modbus`
    // itself is allocation-free end to end — there is no allocator anywhere in
    // its API — so what this actually guards is the demo's own I/O plumbing.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse return runSelfDemo(io);

    if (std.mem.eql(u8, mode, "server")) return runServer(io, &args);
    if (std.mem.eql(u8, mode, "client")) return runClient(io, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("modbus-demo: unknown mode '{s}' (expected `server` or `client`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// no arguments — self-demo
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything `server`/`client` show, folded into one process: a server thread
// listens on an EPHEMERAL loopback port (`:0`, so this can never collide with
// a real slave someone left running) and a client on the calling thread reads
// and writes it, asserting every value that comes back. `std.Io.Threaded` is
// documented "Thread-safe", so the SAME `io` drives both sides — the socket
// handle is the only thing crossing the thread boundary, and `serveConnection`
// below (the same one `server` mode uses) is reused as-is.

fn runSelfDemo(io: std.Io) !u8 {
    var coils = initialCoils();
    var discrete_inputs = initialDiscreteInputs();
    var holding_registers = initialHoldingRegisters();
    var input_registers = initialInputRegisters();

    const db: modbus.server.DataBank = .{
        .coils = .{ .base = 0, .values = &coils },
        .discrete_inputs = .{ .base = 0, .values = &discrete_inputs },
        .holding_registers = .{ .base = 0, .values = &holding_registers },
        .input_registers = .{ .base = 0, .values = &input_registers },
    };
    var server: modbus.server.Server = .init(.{ .unit_id = 1, .framing = .tcp }, db);

    const listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try listen_addr.listen(io, .{});
    defer listener.deinit(io);
    // `:0` resolves to the real port only once bound — `Socket.address` is
    // where that resolution lands (net.zig: "Contains the resolved ephemeral
    // port number if requested").
    const port = listener.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, selfDemoServerThread, .{ io, &server, &listener });
    defer thread.join();

    const connect_addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var tcp = try modbus.TcpTransport.connect(io, connect_addr);
    defer tcp.close();
    var client: modbus.Client = .init(.tcp, tcp.transport());

    std.debug.print("modbus-demo: self-demo — server and client in one process, loopback port {d}\n", .{port});

    // 1. Read all four areas and assert every value against the fixtures that
    // seeded the data bank — the same values `server` mode prints, now
    // checked rather than eyeballed.
    var coils_out: [area_len]bool = undefined;
    try client.readCoils(1, 0, &coils_out);
    if (!std.mem.eql(bool, &coils_out, &initialCoils())) @panic("FC 01 coils did not match the seeded data bank");

    var discrete_out: [area_len]bool = undefined;
    try client.readDiscreteInputs(1, 0, &discrete_out);
    if (!std.mem.eql(bool, &discrete_out, &initialDiscreteInputs())) @panic("FC 02 discrete inputs did not match the seeded data bank");

    var holding_out: [area_len]u16 = undefined;
    try client.readHoldingRegisters(1, 0, &holding_out);
    if (!std.mem.eql(u16, &holding_out, &initialHoldingRegisters())) @panic("FC 03 holding registers did not match the seeded data bank");

    var input_out: [area_len]u16 = undefined;
    try client.readInputRegisters(1, 0, &input_out);
    if (!std.mem.eql(u16, &input_out, &initialInputRegisters())) @panic("FC 04 input registers did not match the seeded data bank");
    std.debug.print("[1] all four areas read back exactly as seeded\n", .{});

    // 2. Write a coil and a register, and prove the write landed by reading
    // it back through a SEPARATE request — an echoed reply alone would not
    // prove the data bank changed (see writeAndReadBack's doc comment above).
    try client.writeSingleCoil(1, 1, true);
    try client.readCoils(1, 0, &coils_out);
    if (!coils_out[1]) @panic("FC 05 write single coil did not take effect");

    try client.writeSingleRegister(1, 2, 0xBEEF);
    var reg_back: [1]u16 = undefined;
    try client.readHoldingRegisters(1, 2, &reg_back);
    if (reg_back[0] != 0xBEEF) @panic("FC 06 write single register did not take effect");
    std.debug.print("[2] coil {d} write and register {d} write both confirmed by a fresh read\n", .{ 1, 2 });

    // 3. The exception path: an address outside every configured window MUST
    // come back as a named protocol exception, not a silent wrong answer.
    var oob: [1]u16 = undefined;
    if (client.readHoldingRegisters(1, out_of_window_addr, &oob)) |_| {
        @panic("FC 03 at an out-of-window address was answered instead of raising IllegalDataAddress");
    } else |err| {
        if (err != error.IllegalDataAddress) return err;
    }
    std.debug.print("[3] a read outside every window correctly raised EXCEPTION IllegalDataAddress\n", .{});

    std.debug.print("modbus-demo: self-demo passed — see `modbus-demo server`/`client` for the full walkthrough\n", .{});
    return 0;
}

/// One accepted connection, served with the exact same loop `server` mode
/// uses. Returns when the client closes its side (the normal ending) or on
/// any I/O error — either way there is nothing further for this thread to do.
fn selfDemoServerThread(io: std.Io, server: *modbus.server.Server, listener: *std.Io.net.Server) void {
    var stream = listener.accept(io) catch |err| {
        std.debug.print("modbus-demo: self-demo: accept failed: {t}\n", .{err});
        return;
    };
    serveConnection(io, server, &stream);
    stream.close(io);
}

// ─────────────────────────────────────────────────────────────────────────────
// the process image — four areas, four kinds of value
// ─────────────────────────────────────────────────────────────────────────────
//
// Every area is 8 points wide and based at address 0, so the SAME address is
// valid in all four — which is the point. A reader who calls FC 04 where they
// meant FC 03 gets a clean answer full of 0x2xxx instead of 0x1xxx rather than
// an error, and that is exactly how the mistake behaves against real hardware.
//
// The windows are deliberately small: address 900 is then outside every one of
// them, which is what the client's exception step relies on.

const area_len = 8;

/// FC 01, read/write bits — a pump, a valve, a contactor. Pattern: every third
/// one on, so a wrong-area read is visible at a glance.
fn initialCoils() [area_len]bool {
    var c: [area_len]bool = @splat(false);
    for (&c, 0..) |*b, i| b.* = (i % 3) == 0;
    return c;
}

/// FC 02, read-only bits — a limit switch, a door contact. Deliberately the
/// OPPOSITE phase of the coils, so "I read the wrong area" is one glance away.
fn initialDiscreteInputs() [area_len]bool {
    var d: [area_len]bool = @splat(false);
    for (&d, 0..) |*b, i| b.* = (i % 2) == 1;
    return d;
}

/// FC 03, read/write words — setpoints. Values carry their own area tag in the
/// top nibble.
fn initialHoldingRegisters() [area_len]u16 {
    var h: [area_len]u16 = @splat(0);
    for (&h, 0..) |*r, i| r.* = 0x1000 + @as(u16, @intCast(i));
    return h;
}

/// FC 04, read-only words — measurements. Tagged 0x2xxx.
fn initialInputRegisters() [area_len]u16 {
    var r: [area_len]u16 = @splat(0);
    for (&r, 0..) |*v, i| v.* = 0x2000 + @as(u16, @intCast(i));
    return r;
}

/// An address no configured window contains. `RegisterArea.contains` is what
/// turns a read here into a spec exception instead of a silent wrap into a
/// neighbour's data — the reason every area carries an explicit base.
const out_of_window_addr: u16 = 900;

// ─────────────────────────────────────────────────────────────────────────────
// server mode
// ─────────────────────────────────────────────────────────────────────────────

const ServerOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    unit: u8 = 1,
    any_unit: bool = false,
    once: bool = false,
};

fn runServer(io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ServerOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--any-unit")) {
            opts.any_unit = true;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            opts.listen = (try nextValue(args, "--listen")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--unit")) {
            opts.unit = (try parseIntArg(u8, args, "--unit")) orelse return local_failure_exit;
        } else {
            std.debug.print("modbus-demo: unknown server option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    // The process image. Plain stack arrays: `DataBank` borrows them, copies
    // nothing, and a simulator animates its device by writing straight into
    // these between requests.
    var coils = initialCoils();
    var discrete_inputs = initialDiscreteInputs();
    var holding_registers = initialHoldingRegisters();
    var input_registers = initialInputRegisters();

    const db: modbus.server.DataBank = .{
        .coils = .{ .base = 0, .values = &coils },
        .discrete_inputs = .{ .base = 0, .values = &discrete_inputs },
        .holding_registers = .{ .base = 0, .values = &holding_registers },
        .input_registers = .{ .base = 0, .values = &input_registers },
    };

    var server: modbus.server.Server = .init(.{
        .unit_id = opts.unit,
        .framing = .tcp,
        .accept_any_unit = opts.any_unit,
        // The three function codes the `Client` has no typed method for. They
        // are OFF by default in `Config` — `exception_status = null` and an
        // empty `slave_id` both mean "not implemented", answered
        // `IllegalFunction` — so a demo that wants to show them has to say so.
        .exception_status = 0x5A,
        .slave_id = "zig-libs modbus-demo",
        .slave_id_extra = &.{ 0x01, 0x00 }, // firmware 1.0, device-specific
        .run_indicator = true,
        .diagnostics = true,
    }, db);

    // The post-write hook: a simulator's seam for "the write landed, now go
    // actuate something". It runs after the data bank is updated and before
    // the reply is built, so what it prints is what the master is about to be
    // told.
    var actuator: Actuator = .{ .db = db };
    server.setWriteHook(actuator.hook());

    const addr = std.Io.net.IpAddress.parse(opts.listen, opts.port) catch |err| {
        std.debug.print("modbus-demo: cannot parse listen address {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };

    // ⚠ Deliberately NOT `reuse_address`. In `std.Io.net` that flag sets
    // SO_REUSEADDR **and SO_REUSEPORT**, and SO_REUSEPORT means a second
    // `modbus-demo server` on this port does not fail to bind: it silently
    // shares the port with the first and the kernel deals connections out
    // between them. A reader with one left running in another terminal would
    // then see half their polls answered by a device they cannot see — which
    // on a protocol whose whole job is to report field values is a far worse
    // outcome than having to wait out a TIME_WAIT.
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("modbus-demo: cannot listen on {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        if (err == error.AddressInUse) std.debug.print(
            \\  Either another modbus-demo server is on that port, or a connection this
            \\  one served is still in TIME_WAIT — wait a moment, or pass --port.
            \\
        , .{});
        return local_failure_exit;
    };
    defer listener.deinit(io);

    std.debug.print("modbus-demo: slave listening on {s}:{d} as unit {d}{s}\n", .{
        opts.listen,                                                         opts.port, opts.unit,
        if (opts.any_unit) " (and every other unit id: --any-unit)" else "",
    });
    printDataBank(db);
    printServerBoundaries();

    while (true) {
        var stream = listener.accept(io) catch |err| {
            std.debug.print("modbus-demo: accept failed: {t}\n", .{err});
            return local_failure_exit;
        };
        serveConnection(io, &server, &stream);
        stream.close(io);
        if (opts.once) break;
    }

    std.debug.print("modbus-demo: bus counters: {d} frames seen, {d} for this unit, {d} exception replies\n", .{
        server.counters.bus_message,
        server.counters.slave_message,
        server.counters.slave_exception_error,
    });
    return 0;
}

/// One connection, until the master hangs up.
///
/// **This is the loop the module does not ship, on purpose.**
/// `Server.handleAdu` is a pure function from one request frame to one reply
/// frame; everything below — listen, accept, delimit, dispatch, write back —
/// is transport policy that belongs to the caller. Delimiting is the only part
/// with any subtlety: Modbus TCP is a byte stream, so a frame is found by
/// reading the 7-byte MBAP header and then exactly the number of bytes its
/// length field announces. Nothing here assumes one read equals one frame,
/// because on TCP it does not.
fn serveConnection(io: std.Io, server: *modbus.server.Server, stream: *std.Io.net.Stream) void {
    var peer_buf: [64]u8 = undefined;
    const peer = peerDescription(stream, &peer_buf);
    std.debug.print("\n-- master connected from {s}\n", .{peer});

    // Paired `Stream.Reader` / `Stream.Writer` on one stream: each keeps its
    // own copy of the two-word `Stream` and its own buffer, which is the same
    // pattern `modules/fleetsim/src/tcp.zig` uses against this same `Server`.
    var rbuf: [modbus.tcp.max_adu_len]u8 = undefined;
    var wbuf: [modbus.tcp.max_adu_len]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var adu: [modbus.tcp.max_adu_len]u8 = undefined;
    var out: [modbus.tcp.max_adu_len]u8 = undefined;
    var served: usize = 0;

    while (true) {
        sr.interface.readSliceAll(adu[0..modbus.tcp.header_len]) catch |err| switch (err) {
            error.EndOfStream => break, // the master hung up: the normal ending
            error.ReadFailed => {
                std.debug.print("-- read from {s} failed\n", .{peer});
                break;
            },
        };
        // MBAP: transaction id (2) | protocol id (2) | length (2) | unit (1).
        // The length field counts the unit id and the PDU, so the whole frame
        // is 6 + length.
        const len_field: usize = std.mem.readInt(u16, adu[4..6], .big);
        const total = 6 + len_field;
        if (len_field < 2 or total > adu.len) {
            std.debug.print("-- {s} sent an impossible MBAP length ({d}); hanging up\n", .{ peer, len_field });
            break;
        }
        sr.interface.readSliceAll(adu[modbus.tcp.header_len..total]) catch {
            std.debug.print("-- {s} truncated a frame mid-PDU\n", .{peer});
            break;
        };

        const request = adu[0..total];
        logRequest(request);

        const reply = server.handleAdu(request, &out) catch |err| {
            // The ONLY error this can return is `BufferTooSmall`, and it is a
            // local programming mistake, not something a peer can provoke:
            // everything a master can get wrong becomes an exception response
            // or a dropped frame. `out` is `tcp.max_adu_len`, so this is
            // unreachable in practice — and is still handled rather than
            // `catch unreachable`, because an example that models a
            // never-happens branch as a panic is teaching a habit.
            std.debug.print("-- reply buffer too small ({t}); hanging up\n", .{err});
            break;
        } orelse {
            // `null` is "a real device would say nothing here": a frame for
            // another unit id, a structurally impossible frame, or (on RTU) a
            // broadcast or a bad CRC. It is NOT an error, and answering it
            // would be wrong. The master, meanwhile, sees nothing at all —
            // which is why every Modbus master needs a response timeout.
            std.debug.print("   -> silent (not addressed to this device, or unusable). " ++ "The master will sit in its response timeout.\n", .{});
            continue;
        };

        sw.interface.writeAll(reply) catch break;
        sw.interface.flush() catch break;
        logReply(reply);
        served += 1;
    }

    std.debug.print("-- master {s} disconnected after {d} exchange(s)\n", .{ peer, served });
}

/// `WriteHook` in one value: what a simulator hangs its actuation off.
const Actuator = struct {
    db: modbus.server.DataBank,
    writes: usize = 0,

    fn hook(self: *Actuator) modbus.server.WriteHook {
        return .{ .ctx = self, .onWriteFn = onWrite };
    }

    /// Runs AFTER the data bank has been updated, so the new value is already
    /// readable through the same borrowed slices the bank holds.
    fn onWrite(ctx: *anyopaque, event: modbus.server.WriteEvent) void {
        const self: *Actuator = @ptrCast(@alignCast(ctx));
        self.writes += 1;
        switch (event.area) {
            .coils => {
                const i = self.db.coils.index(event.addr) orelse return;
                std.debug.print("   ~> actuate: coil {d} is now {s} ({d} point(s) written)\n", .{
                    event.addr,
                    if (self.db.coils.values[i]) "ON" else "OFF",
                    event.count,
                });
            },
            .holding_registers => {
                const i = self.db.holding_registers.index(event.addr) orelse return;
                std.debug.print("   ~> actuate: holding register {d} is now 0x{X:0>4} ({d} register(s) written)\n", .{
                    event.addr,
                    self.db.holding_registers.values[i],
                    event.count,
                });
            },
            // Unreachable by construction — `WriteEvent.area` is documented as
            // always `.coils` or `.holding_registers`, because the other two
            // areas are read-only in the protocol. Named rather than assumed.
            .discrete_inputs, .input_registers => {},
        }
    }
};

fn printDataBank(db: modbus.server.DataBank) void {
    var bits: [2 * area_len]u8 = undefined;
    std.debug.print(
        \\modbus-demo: the process image this device serves — four SEPARATE areas,
        \\  all based at address 0, so address N exists four times over:
        \\
    , .{});
    std.debug.print("  FC 01 coils           rw [0..{d}]  {s}\n", .{ area_len - 1, bitsText(db.coils.values, &bits) });
    std.debug.print("  FC 02 discrete inputs ro [0..{d}]  {s}\n", .{ area_len - 1, bitsText(db.discrete_inputs.values, &bits) });
    std.debug.print("  FC 03 holding regs    rw [0..{d}]  ", .{area_len - 1});
    printRegisters(db.holding_registers.values);
    std.debug.print("  FC 04 input regs      ro [0..{d}]  ", .{area_len - 1});
    printRegisters(db.input_registers.values);
    std.debug.print("  Address {d} is in NONE of them — that is the exception the client provokes.\n", .{out_of_window_addr});
}

fn printServerBoundaries() void {
    std.debug.print(
        \\modbus-demo: what this server does NOT do, so nothing surprises you:
        \\  - one connection at a time. A second master waits in the kernel's accept
        \\    backlog. The module has no concurrency model at all — `handleAdu` is a
        \\    pure function, and the loop around it is this file's, not the module's.
        \\  - no response timeout of its own, and none is needed: it only ever speaks
        \\    when spoken to.
        \\  - reads and writes hit the arrays directly. There is no scan cycle, no
        \\    program execution, no retentive memory: this is not a PLC emulator.
        \\  - unit ids other than the one above are answered with SILENCE, not with an
        \\    exception — that is what a device on a shared bus must do.
        \\
    , .{});
}

/// `127.0.0.1 port 41234`, the way a daemon names a peer in its log. `accept`
/// hands back a `Stream` and no address, so this asks the socket.
fn peerDescription(stream: *std.Io.net.Stream, buf: *[64]u8) []const u8 {
    var sa: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(@TypeOf(sa));
    std.posix.getpeername(stream.socket.handle, @ptrCast(&sa), &len) catch return "an unnamed peer";
    if (sa.family != std.posix.AF.INET) return "a non-IPv4 peer";
    const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&sa));
    const octets: [4]u8 = @bitCast(in.addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d} port {d}", .{
        octets[0], octets[1], octets[2], octets[3], std.mem.bigToNative(u16, in.port),
    }) catch "a peer with an unprintable address";
}

fn logRequest(adu: []const u8) void {
    const frame = modbus.tcp.decodeAdu(adu) catch {
        std.debug.print("   <- {d} bytes that are not a valid MBAP frame\n", .{adu.len});
        return;
    };
    std.debug.print("   <- txid {d:>5}  unit {d:>3}  FC 0x{X:0>2} {s}  ({d} PDU bytes)\n", .{
        frame.transaction_id, frame.unit, frame.pdu[0], functionName(frame.pdu[0]), frame.pdu.len,
    });
}

fn logReply(adu: []const u8) void {
    const frame = modbus.tcp.decodeAdu(adu) catch return;
    const fc = frame.pdu[0];
    if (fc & 0x80 != 0 and frame.pdu.len >= 2) {
        std.debug.print("   -> EXCEPTION 0x{X:0>2} to FC 0x{X:0>2} {s}\n", .{ frame.pdu[1], fc & 0x7F, functionName(fc & 0x7F) });
        return;
    }
    std.debug.print("   -> ok, {d} PDU bytes\n", .{frame.pdu.len});
}

// ─────────────────────────────────────────────────────────────────────────────
// client mode
// ─────────────────────────────────────────────────────────────────────────────

const ClientOptions = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    unit: u8 = 1,
    silent_probe: bool = false,
};

fn runClient(io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ClientOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--silent-probe")) {
            opts.silent_probe = true;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = (try nextValue(args, "--host")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--unit")) {
            opts.unit = (try parseIntArg(u8, args, "--unit")) orelse return local_failure_exit;
        } else {
            std.debug.print("modbus-demo: unknown client option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("modbus-demo: cannot parse {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    var tcp = modbus.TcpTransport.connect(io, addr) catch |err| {
        std.debug.print("modbus-demo: cannot connect to {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    defer tcp.close();

    // `TcpTransport` is the module's own convenience adapter over
    // `std.Io.net`; the seam it implements, `Transport`, is what makes the
    // client offline-testable. Anything with a `send request ADU / receive one
    // reply ADU` shape fits — a serial port, a TLS tunnel, a fake in a test.
    var client: modbus.Client = .init(.tcp, tcp.transport());

    std.debug.print("modbus-demo: master connected to {s}:{d}, addressing unit {d}\n\n", .{ opts.host, opts.port, opts.unit });

    var failures: usize = 0;
    failures += @intFromBool(!readAllFourAreas(&client, opts.unit));
    failures += @intFromBool(!writeAndReadBack(&client, opts.unit));
    failures += @intFromBool(!serverOnlyFunctions(&client, opts.unit));
    failures += @intFromBool(!exceptionPath(&client, opts.unit));

    if (opts.silent_probe) silentProbe(&client, opts.unit);

    std.debug.print("\nmodbus-demo: done, {d} step(s) failed\n", .{failures});
    return if (failures == 0) 0 else local_failure_exit;
}

/// Step 1 — the whole point of the demo: four areas, four answers, one
/// address. Every read below asks for address 0..7; nothing but the FUNCTION
/// CODE distinguishes them, and the values prove they landed in four different
/// places.
fn readAllFourAreas(client: *modbus.Client, unit: u8) bool {
    std.debug.print("[1] the four data areas, all read from the SAME addresses 0..{d}\n", .{area_len - 1});
    var bits: [2 * area_len]u8 = undefined;

    var coils: [area_len]bool = undefined;
    client.readCoils(unit, 0, &coils) catch |err| return stepFailed("FC 01 read coils", err);
    std.debug.print("    FC 01 coils            {s}\n", .{bitsText(&coils, &bits)});

    var inputs: [area_len]bool = undefined;
    client.readDiscreteInputs(unit, 0, &inputs) catch |err| return stepFailed("FC 02 read discrete inputs", err);
    std.debug.print("    FC 02 discrete inputs  {s}\n", .{bitsText(&inputs, &bits)});

    var holding: [area_len]u16 = undefined;
    client.readHoldingRegisters(unit, 0, &holding) catch |err| return stepFailed("FC 03 read holding registers", err);
    std.debug.print("    FC 03 holding regs     ", .{});
    printRegisters(&holding);

    var input_regs: [area_len]u16 = undefined;
    client.readInputRegisters(unit, 0, &input_regs) catch |err| return stepFailed("FC 04 read input registers", err);
    std.debug.print("    FC 04 input regs       ", .{});
    printRegisters(&input_regs);

    std.debug.print("    (0x1xxx vs 0x2xxx: FC 03 and FC 04 are DIFFERENT memory, not two spellings of one.)\n\n", .{});
    return true;
}

/// Step 2 — one write of each writable kind, each confirmed by reading it
/// back. The read-back is not ceremony: FC 05 and FC 06 replies are a pure
/// echo of the request, so a device that ignored the write can still produce a
/// perfectly valid, perfectly wrong-headed "yes". Only a read proves anything.
fn writeAndReadBack(client: *modbus.Client, unit: u8) bool {
    std.debug.print("[2] writes — a coil (FC 05) and a register (FC 06), each read back\n", .{});
    var bits: [2 * area_len]u8 = undefined;

    const coil_addr: u16 = 1; // was OFF in the initial pattern
    client.writeSingleCoil(unit, coil_addr, true) catch |err| return stepFailed("FC 05 write single coil", err);
    var coils: [area_len]bool = undefined;
    client.readCoils(unit, 0, &coils) catch |err| return stepFailed("FC 01 read-back", err);
    std.debug.print("    FC 05 coil {d} := ON     -> coils now {s}\n", .{ coil_addr, bitsText(&coils, &bits) });

    const reg_addr: u16 = 2;
    client.writeSingleRegister(unit, reg_addr, 0xBEEF) catch |err| return stepFailed("FC 06 write single register", err);
    var one: [1]u16 = undefined;
    client.readHoldingRegisters(unit, reg_addr, &one) catch |err| return stepFailed("FC 03 read-back", err);
    std.debug.print("    FC 06 reg {d}  := 0xBEEF -> reads back 0x{X:0>4}\n", .{ reg_addr, one[0] });

    // FC 10, the multi-register write, on the same area — one transaction
    // instead of three.
    const block = [_]u16{ 0x0AAA, 0x0BBB, 0x0CCC };
    client.writeMultipleRegisters(unit, 4, &block) catch |err| return stepFailed("FC 10 write multiple registers", err);
    var back: [3]u16 = undefined;
    client.readHoldingRegisters(unit, 4, &back) catch |err| return stepFailed("FC 03 read-back", err);
    std.debug.print("    FC 10 regs 4..6        -> reads back ", .{});
    printRegisters(&back);

    // A write to a READ-ONLY area is not refused by the protocol — it is
    // simply unaddressable: there is no function code that writes a discrete
    // input or an input register at all. Said out loud because "why can't I
    // write my input register" is the second question after "which area am I
    // in".
    std.debug.print("    (there is NO function code that writes a discrete input or an\n" ++
        "     input register — those areas are read-only by construction, not by policy.)\n\n", .{});
    return true;
}

/// Step 3 — the three function codes the `Server` answers and the `Client`
/// cannot ask for. Shown rather than hidden: a demo that only exercised the
/// typed methods would leave a reader believing the client is complete.
fn serverOnlyFunctions(client: *modbus.Client, unit: u8) bool {
    std.debug.print("[3] function codes the Client has no typed method for, built by hand\n", .{});
    var reply_buf: [modbus.tcp.max_adu_len]u8 = undefined;

    // FC 0x11 Report Slave ID — the cheapest of the three: the request PDU is
    // the single function-code byte, and the reply is byte count, id bytes,
    // run indicator, then device-specific data.
    {
        const request = [_]u8{@intFromEnum(modbus.FunctionCode.report_slave_id)};
        const reply = rawExchange(client, unit, &request, &reply_buf) catch |err|
            return stepFailed("FC 11 report slave id", err);
        // `pdu.checkFunction` IS reusable here: `FunctionCode` names 0x11, so
        // the module still maps `0x91 + code` to a typed exception error for
        // us. What it cannot do is parse the payload — that layout is
        // device-specific by definition.
        const body = modbus.pdu.checkFunction(reply, .report_slave_id) catch |err|
            return stepFailed("FC 11 report slave id", err);
        if (body.len < 2 or body[0] != body.len - 1) return stepFailed("FC 11 report slave id", error.MalformedResponse);
        const id = body[1 .. body.len - 1 - 2];
        const run = body[body.len - 3];
        std.debug.print("    FC 11 slave id  \"{s}\", run indicator {s}, {d} extra byte(s)\n", .{
            id, if (run == 0xFF) "ON" else "OFF", body.len - 1 - id.len - 1,
        });
    }

    // FC 0x07 Read Exception Status — the same shape: an empty request, a
    // one-byte answer. Eight vendor-defined bits, historically the coils a
    // device wanted a master to see without a full poll.
    {
        const request = [_]u8{@intFromEnum(modbus.FunctionCode.read_exception_status)};
        const reply = rawExchange(client, unit, &request, &reply_buf) catch |err|
            return stepFailed("FC 07 read exception status", err);
        const body = modbus.pdu.checkFunction(reply, .read_exception_status) catch |err|
            return stepFailed("FC 07 read exception status", err);
        if (body.len != 1) return stepFailed("FC 07 read exception status", error.MalformedResponse);
        std.debug.print("    FC 07 exception status 0x{X:0>2}\n", .{body[0]});
    }

    // FC 0x08 Diagnostics, sub-function 0x0000 "return query data" — a loopback
    // the master can use to prove the link without touching any point.
    {
        var request: [5]u8 = undefined;
        request[0] = @intFromEnum(modbus.FunctionCode.diagnostics);
        std.mem.writeInt(u16, request[1..3], 0x0000, .big); // return query data
        std.mem.writeInt(u16, request[3..5], 0xA537, .big); // the echoed payload
        const reply = rawExchange(client, unit, &request, &reply_buf) catch |err|
            return stepFailed("FC 08 diagnostics", err);
        const body = modbus.pdu.checkFunction(reply, .diagnostics) catch |err|
            return stepFailed("FC 08 diagnostics", err);
        if (body.len != 4) return stepFailed("FC 08 diagnostics", error.MalformedResponse);
        const echoed = std.mem.readInt(u16, body[2..4], .big);
        std.debug.print("    FC 08 loopback  sent 0xA537, got 0x{X:0>4} — {s}\n", .{
            echoed, if (echoed == 0xA537) "echoed" else "NOT echoed",
        });
    }

    std.debug.print("\n", .{});
    return true;
}

/// ⚠ **The module's doc comment on `FunctionCode` says a master that wants
/// the server-only codes "can build the 1-3 byte PDU by hand and use
/// `Client`'s framing". It cannot: `Client.exchangePdu` — the function that
/// wraps a PDU, runs the round-trip, and validates the reply frame — is
/// private, and there is no public equivalent.** So "use `Client`'s framing"
/// means re-implementing it, which is this function: pick a transaction id
/// from the client's own counter, encode, exchange, decode, and re-check the
/// transaction id and unit that `exchangePdu` would have checked. Twelve lines
/// that already exist inside the module.
///
/// It is not *hard* — everything needed is public (`tcp.encodeAdu`,
/// `tcp.decodeAdu`, `Client.transport`, `Client.next_transaction_id`) and the
/// errors are the same flat `Client.Error`. But it is duplicated, and it is
/// duplicated in the one place a caller is least equipped to get right: a
/// re-implementation that forgot the transaction-id check would pass every
/// test against a well-behaved device and mismatch replies under load.
///
/// Two further sharp edges a reader should not have to find alone:
///   - the transaction id MUST come from `client.next_transaction_id`, not
///     from a counter of your own, or a hand-built request and a typed one can
///     be in flight with the same id;
///   - this returns the reply PDU only. `pdu.checkFunction` handles the
///     exception mapping for any code `FunctionCode` names — which is all
///     three server-only ones — but for a function code outside that enum
///     (0x2B, say) there is no `FunctionCode` to pass, and the caller decodes
///     `fc | 0x80` themselves. `exceptionError` is public for exactly that.
fn rawExchange(
    client: *modbus.Client,
    unit: u8,
    request_pdu: []const u8,
    reply_buf: *[modbus.tcp.max_adu_len]u8,
) modbus.Client.Error![]const u8 {
    var adu_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    const txid = client.next_transaction_id;
    client.next_transaction_id +%= 1;
    const adu = try modbus.tcp.encodeAdu(&adu_buf, txid, unit, request_pdu);
    const reply = try client.transport.exchange(adu, reply_buf);
    const frame = try modbus.tcp.decodeAdu(reply);
    if (frame.transaction_id != txid) return error.TransactionIdMismatch;
    if (frame.unit != unit) return error.UnitMismatch;
    return frame.pdu;
}

/// Step 4 — the typed-error path, over a real socket rather than in-process.
///
/// A Modbus exception is not a transport failure and not a bug: it is the
/// device answering "no" in the protocol's own vocabulary, and a master that
/// treats it as an I/O error will retry forever against a device that is
/// working perfectly. `Client.Error` being one FLAT union is what makes the
/// distinction a plain `switch` — no error-set gymnastics, no `anyerror`.
fn exceptionPath(client: *modbus.Client, unit: u8) bool {
    std.debug.print("[4] the exception path — the device says no, in protocol terms\n", .{});

    // 4a. An address outside every configured window. The device answers
    // ILLEGAL DATA ADDRESS rather than wrapping into whatever happens to be
    // next in memory — which is the whole reason `DataBank`'s areas carry an
    // explicit base and length.
    var oob: [1]u16 = undefined;
    if (client.readHoldingRegisters(unit, out_of_window_addr, &oob)) |_| {
        std.debug.print("    FC 03 @ {d}: answered — the window is wider than this demo assumed\n", .{out_of_window_addr});
        return false;
    } else |err| {
        std.debug.print("    FC 03 @ {d}: {s}\n", .{ out_of_window_addr, classify(err) });
        if (err != error.IllegalDataAddress) return false;
    }

    // 4b. A quantity over the spec limit for FC 03 (125 registers). Caught
    // LOCALLY, before a single byte is sent — `EncodeError.InvalidQuantity`
    // sits in the same flat union, so the same `switch` sorts a request that
    // never left the building from one the device refused.
    var too_many: [200]u16 = undefined;
    if (client.readHoldingRegisters(unit, 0, &too_many)) |_| {
        std.debug.print("    FC 03 x200: accepted — the spec limit is not being enforced\n", .{});
        return false;
    } else |err| {
        std.debug.print("    FC 03 x200 registers: {s}\n", .{classify(err)});
        if (err != error.InvalidQuantity) return false;
    }

    // 4c. A function code this device does not implement, and that
    // `FunctionCode` does not even name: 0x2B, Encapsulated Interface
    // Transport. There is no `FunctionCode` variant to hand `checkFunction`,
    // so the exception is decoded here by hand — the honest shape of asking a
    // device for something outside the module's vocabulary.
    {
        var reply_buf: [modbus.tcp.max_adu_len]u8 = undefined;
        const request = [_]u8{ 0x2B, 0x0E, 0x01, 0x00 }; // read device identification
        if (rawExchange(client, unit, &request, &reply_buf)) |reply| {
            if (reply.len >= 2 and reply[0] == 0x2B | 0x80) {
                std.debug.print("    FC 2B (unnamed by this module): {s}\n", .{classify(modbus.exceptionError(reply[1]))});
            } else {
                std.debug.print("    FC 2B: answered with {d} bytes — this device implements it\n", .{reply.len});
            }
        } else |err| {
            std.debug.print("    FC 2B: {s}\n", .{classify(err)});
            return false;
        }
    }

    return true;
}

/// One switch over the whole flat `Client.Error`, sorting three genuinely
/// different situations that a caller must not confuse:
///
///  - the device answered, and its answer was "no" (a protocol exception);
///  - the request never left this process (a local encoding limit);
///  - the conversation itself broke (transport, or a reply that was not a
///    valid frame).
fn classify(err: modbus.Client.Error) []const u8 {
    return switch (err) {
        // ── the device answered "no" — spec §7 exception codes ──────────────
        error.IllegalFunction => "EXCEPTION IllegalFunction — the device does not implement that function code",
        error.IllegalDataAddress => "EXCEPTION IllegalDataAddress — outside every window this device serves",
        error.IllegalDataValue => "EXCEPTION IllegalDataValue — the value or quantity is not one it will take",
        error.ServerDeviceFailure => "EXCEPTION ServerDeviceFailure — an unrecoverable fault in the device",
        error.Acknowledge => "EXCEPTION Acknowledge — accepted, still working; poll again later",
        error.ServerDeviceBusy => "EXCEPTION ServerDeviceBusy — retry the same request later",
        error.NegativeAcknowledge => "EXCEPTION NegativeAcknowledge — the programming function was refused",
        error.MemoryParityError => "EXCEPTION MemoryParityError — extended-file parity fault",
        error.GatewayPathUnavailable => "EXCEPTION GatewayPathUnavailable — a gateway could not route this",
        error.GatewayTargetFailed => "EXCEPTION GatewayTargetFailed — the gateway got no answer from the target",
        error.UnknownException => "EXCEPTION (a code outside the published table — vendors do this)",

        // ── never left this process ─────────────────────────────────────────
        error.InvalidQuantity => "LOCAL InvalidQuantity — over the spec limit for this function code; no bytes were sent",
        error.AddressOverflow => "LOCAL AddressOverflow — address + quantity runs past the 16-bit space",
        error.PduTooLong, error.BufferTooSmall => "LOCAL a buffer/PDU size limit; no bytes were sent",

        // ── the conversation broke ──────────────────────────────────────────
        error.Timeout => "TRANSPORT Timeout — no reply in time",
        error.Canceled => "TRANSPORT Canceled — the blocking wait was canceled (std.Io), NOT a device failure",
        error.TransportFailed => "TRANSPORT failed — the socket, not the protocol",
        error.ShortFrame, error.FrameTooLong, error.LengthMismatch => "MALFORMED the reply is not a well-formed frame",
        error.BadCrc => "MALFORMED RTU CRC mismatch — line noise, or a device mid-frame",
        error.ProtocolIdMismatch => "MALFORMED MBAP protocol id is not 0 — that is not Modbus TCP",
        error.TransactionIdMismatch => "MALFORMED a reply to a DIFFERENT request — replies are out of step",
        error.UnitMismatch => "MALFORMED the reply came from another unit id",
        error.FunctionMismatch => "MALFORMED the reply's function code matches neither the request nor its exception",
        error.MalformedResponse => "MALFORMED byte counts or echoed fields disagree with the request",
    };
}

/// ⚠ **A module gap, demonstrated rather than described.**
///
/// A Modbus slave stays SILENT — not "returns an error", silent — for a frame
/// addressed to another unit id, for an RTU broadcast, for a bad CRC, and in
/// listen-only mode. `Server.handleAdu` models all of that correctly by
/// returning `null`. But `TcpTransport.exchangeFn` reads the reply with no
/// deadline of any kind, so a master that provokes one of those cases blocks
/// **forever**: `TransportError.Timeout` is in the error set and `TcpTransport`
/// can never produce it. Every real Modbus master has a response timeout —
/// it is the single most important knob on the protocol — and a caller who
/// needs one has to write their own `Transport` today.
///
/// Only runs under `--silent-probe`, and says so before it hangs.
fn silentProbe(client: *modbus.Client, unit: u8) void {
    const other: u8 = if (unit == 9) 8 else 9;
    std.debug.print(
        \\
        \\[5] --silent-probe: addressing unit {d}, which this slave does not answer for.
        \\    A real device stays SILENT. `TcpTransport` has no read deadline, so this
        \\    call cannot return: it will block until the peer closes or you interrupt
        \\    it. `TransportError.Timeout` exists in the error set and this transport
        \\    can never produce it — a caller who needs one writes their own Transport.
        \\
    , .{other});
    var out: [1]u16 = undefined;
    client.readHoldingRegisters(other, 0, &out) catch |err| {
        std.debug.print("    returned: {s}\n", .{classify(err)});
        return;
    };
    std.debug.print("    answered — that slave is in --any-unit mode\n", .{});
}

fn stepFailed(what: []const u8, err: modbus.Client.Error) bool {
    std.debug.print("    {s}: {s}\n", .{ what, classify(err) });
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// small shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn bitsText(bits: []const bool, buf: []u8) []const u8 {
    var i: usize = 0;
    for (bits) |b| {
        if (i != 0) {
            buf[i] = ' ';
            i += 1;
        }
        buf[i] = if (b) '1' else '0';
        i += 1;
    }
    return buf[0..i];
}

fn printRegisters(regs: []const u16) void {
    for (regs, 0..) |r, i| std.debug.print("{s}0x{X:0>4}", .{ if (i == 0) "" else " ", r });
    std.debug.print("\n", .{});
}

/// The 12 codes `FunctionCode` names, plus an honest label for everything
/// else. A `switch` on the raw byte rather than `@enumFromInt`, because the
/// enum is exhaustive and a peer may send any byte at all.
fn functionName(fc: u8) []const u8 {
    return switch (fc) {
        0x01 => "read coils",
        0x02 => "read discrete inputs",
        0x03 => "read holding registers",
        0x04 => "read input registers",
        0x05 => "write single coil",
        0x06 => "write single register",
        0x07 => "read exception status",
        0x08 => "diagnostics",
        0x0F => "write multiple coils",
        0x10 => "write multiple registers",
        0x11 => "report slave id",
        0x17 => "read/write multiple registers",
        else => "(not implemented here)",
    };
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) !?[]const u8 {
    return args.next() orelse {
        std.debug.print("modbus-demo: {s} needs a value\n", .{flag});
        return null;
    };
}

fn parseIntArg(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !?T {
    const text = (try nextValue(args, flag)) orelse return null;
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("modbus-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return null;
    };
}
