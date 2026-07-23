// SPDX-License-Identifier: MIT

//! dnp3.outstation — the **outstation** side of the conversation, as a pure
//! function from one application fragment to one application fragment.
//!
//! Its reason to exist is fleet simulation. A responder that speaks the real
//! wire format lets a whole DNP3 master stack be exercised against hundreds of
//! simulated RTUs with no hardware, and it is what makes the round-trip
//! goldens in `goldens.zig` possible.
//!
//! Shape (the same one `iec104`'s outstation, `s7comm`'s responder and
//! `modbus`'s server use):
//!
//! - `handle(request, now_ms, out) -> ?Reply` takes one whole application
//!   request fragment and writes one whole application response fragment.
//!   `null` means "say nothing" — a CONFIRM, or a broadcast that asks for no
//!   reply. The link and transport layers below it stay the caller's job:
//!   `dnp3.sendFragment` / `dnp3.FrameReceiver` already do that, and
//!   `Session` in this file wires the three together for callers who want it
//!   done for them.
//! - No threads, no owned timers, no allocation. Every buffer and every point
//!   is the caller's, and every deadline is driven by an injected `now_ms`.
//!
//! What is implemented
//! -------------------
//! - **Function codes**: READ (class 0/1/2/3 polls and specific
//!   group/variation reads), WRITE (IIN restart clear + time-and-date),
//!   SELECT / OPERATE / DIRECT_OPERATE / DIRECT_OPERATE_NO_ACK for CROB (g12)
//!   and analog output blocks (g41), COLD_RESTART, WARM_RESTART,
//!   DELAY_MEASURE, ENABLE / DISABLE_UNSOLICITED, IMMEDIATE_FREEZE (+ no-ack
//!   and freeze-clear), ASSIGN_CLASS, RECORD_CURRENT_TIME and CONFIRM.
//!   Anything else answers with IIN2.FUNC_NOT_SUPPORTED, which is what a
//!   master needs to see to stop asking.
//! - **IIN**: device restart (set at power-up, cleared only by an explicit
//!   WRITE of g80v1 index 7), class 1/2/3 events available, need-time, event
//!   buffer overflow, plus the per-request bits (func-not-supported,
//!   object-unknown, parameter-error, already-executing).
//! - **Event buffering**: a bounded caller-owned ring per class, reported
//!   oldest-first with the correct event group/variation, and retired only
//!   when the master's CONFIRM arrives. A response that carries events always
//!   sets CON. Overflow drops the oldest and raises IIN2.3, as §11 requires.
//! - **Static object model**: binary input (g1), double-bit binary input
//!   (g3), binary output status (g10), counter (g20), frozen counter (g21),
//!   analog input (g30) and analog output status (g40), in the with-flags,
//!   without-flags, 16/32-bit and float variations `records.zig` tabulates,
//!   with 8- and 16-bit start-stop, 8- and 16-bit count-with-index, and
//!   all-objects qualifiers.
//! - **Fragmentation**: a response too large for one fragment splits with
//!   correct FIR/FIN/SEQ and a resumable cursor; each non-final fragment
//!   requests a confirm, and `next()` produces the following one.
//! - **Select-before-operate**: the select is remembered with its arm time and
//!   its exact object bytes; an OPERATE that does not match, or that arrives
//!   after `select_timeout_ms`, is answered NO_SELECT / TIMEOUT rather than
//!   executed.
//!
//! Deliberately not implemented — see README "Scope": unsolicited *retry*
//! policy (the fragment builder is here, the retry timer is the caller's),
//! file transfer (g70), data sets (g85-g88), device attributes (g0),
//! octet strings (g110/g111), time-and-interval (g50v4), and Secure
//! Authentication integration (`sa.zig` is a separate codec; nothing here
//! wraps a fragment in g120 objects).
//!
//! Provenance: clean-room from IEEE 1815-2012. Behaviour cross-checked
//! against opendnp3 (Apache-2.0) as a black-box peer only — its `master-demo`
//! drove this outstation over a real socket and its `decoder` tool dissected
//! the bytes; no source was consulted or copied.

const std = @import("std");
const application = @import("application.zig");
const objects = @import("objects.zig");
const records = @import("records.zig");
const link = @import("link.zig");
const transport = @import("transport.zig");

pub const Iin = application.Iin;
pub const FunctionCode = application.FunctionCode;
pub const CommandStatus = objects.g12.CommandStatus;
pub const Flags = records.Flags;
pub const DoubleBit = records.DoubleBit;
pub const PointKind = records.PointKind;

// ── classes ─────────────────────────────────────────────────────────────────

/// Event class assignment (§11.2). `none` means the point generates no
/// events at all; class 0 is not an event class (it is the static scan).
pub const EventClass = enum(u2) { class1 = 1, class2 = 2, class3 = 3 };

// ── the point database ──────────────────────────────────────────────────────

/// One binary input point.
pub const BinaryInput = struct {
    value: bool = false,
    flags: Flags = .{ .online = true },
    /// Which event class this point's changes land in; null = no events.
    class: ?EventClass = .class1,
    /// The variation a class-0 (static) scan reports this point in.
    static_variation: u8 = 1,
    /// The variation an event report uses.
    event_variation: u8 = 2,
};

pub const DoubleBitInput = struct {
    value: DoubleBit = .determined_off,
    flags: Flags = .{ .online = true },
    class: ?EventClass = .class1,
    static_variation: u8 = 2,
    event_variation: u8 = 2,
};

pub const BinaryOutputStatus = struct {
    value: bool = false,
    flags: Flags = .{ .online = true },
    class: ?EventClass = null,
    static_variation: u8 = 2,
    event_variation: u8 = 2,
    /// Set false to make every command against this point fail NOT_SUPPORTED.
    supports_commands: bool = true,
};

pub const Counter = struct {
    value: u32 = 0,
    flags: Flags = .{ .online = true },
    class: ?EventClass = .class3,
    static_variation: u8 = 1,
    event_variation: u8 = 1,
};

pub const FrozenCounter = struct {
    value: u32 = 0,
    flags: Flags = .{ .online = true },
    class: ?EventClass = null,
    static_variation: u8 = 1,
    event_variation: u8 = 1,
};

pub const AnalogInput = struct {
    value: f64 = 0,
    flags: Flags = .{ .online = true },
    class: ?EventClass = .class2,
    static_variation: u8 = 1,
    event_variation: u8 = 1,
    /// Reject an analog *output* write outside these bounds. Unused for
    /// inputs; kept here so both analog kinds share one struct shape is not
    /// needed — see `AnalogOutputStatus`.
    _pad: void = {},
};

pub const AnalogOutputStatus = struct {
    value: f64 = 0,
    flags: Flags = .{ .online = true },
    class: ?EventClass = null,
    static_variation: u8 = 1,
    event_variation: u8 = 1,
    supports_commands: bool = true,
    /// Inclusive bounds an OPERATE must fall inside; a value outside them is
    /// answered OUT_OF_RANGE instead of being written.
    min: f64 = -std.math.floatMax(f64),
    max: f64 = std.math.floatMax(f64),
};

/// The outstation's point database: seven caller-owned arrays, indexed from
/// 0. Nothing is copied and nothing is allocated — the caller mutates the
/// backing slices to animate the process image, and calls `reportChange` to
/// turn a mutation into an event.
pub const Database = struct {
    binary_inputs: []BinaryInput = &.{},
    double_bit_inputs: []DoubleBitInput = &.{},
    binary_outputs: []BinaryOutputStatus = &.{},
    counters: []Counter = &.{},
    frozen_counters: []FrozenCounter = &.{},
    analog_inputs: []AnalogInput = &.{},
    analog_outputs: []AnalogOutputStatus = &.{},

    pub fn count(self: Database, kind: PointKind) usize {
        return switch (kind) {
            .binary_input => self.binary_inputs.len,
            .double_bit_input => self.double_bit_inputs.len,
            .binary_output_status => self.binary_outputs.len,
            .counter => self.counters.len,
            .frozen_counter => self.frozen_counters.len,
            .analog_input => self.analog_inputs.len,
            .analog_output_status => self.analog_outputs.len,
        };
    }

    fn staticVariation(self: Database, kind: PointKind, index: usize) u8 {
        return switch (kind) {
            .binary_input => self.binary_inputs[index].static_variation,
            .double_bit_input => self.double_bit_inputs[index].static_variation,
            .binary_output_status => self.binary_outputs[index].static_variation,
            .counter => self.counters[index].static_variation,
            .frozen_counter => self.frozen_counters[index].static_variation,
            .analog_input => self.analog_inputs[index].static_variation,
            .analog_output_status => self.analog_outputs[index].static_variation,
        };
    }

    fn flagsOf(self: Database, kind: PointKind, index: usize) Flags {
        return switch (kind) {
            .binary_input => self.binary_inputs[index].flags,
            .double_bit_input => self.double_bit_inputs[index].flags,
            .binary_output_status => self.binary_outputs[index].flags,
            .counter => self.counters[index].flags,
            .frozen_counter => self.frozen_counters[index].flags,
            .analog_input => self.analog_inputs[index].flags,
            .analog_output_status => self.analog_outputs[index].flags,
        };
    }

    fn valueOf(self: Database, kind: PointKind, index: usize) records.Value {
        return switch (kind) {
            .binary_input => .{ .binary = self.binary_inputs[index].value },
            .double_bit_input => .{ .double_bit = self.double_bit_inputs[index].value },
            .binary_output_status => .{ .binary = self.binary_outputs[index].value },
            .counter => .{ .counter = self.counters[index].value },
            .frozen_counter => .{ .counter = self.frozen_counters[index].value },
            .analog_input => analogValue(self.analog_inputs[index].value, self.analog_inputs[index].static_variation),
            .analog_output_status => analogValue(self.analog_outputs[index].value, self.analog_outputs[index].static_variation),
        };
    }

    fn classOf(self: Database, kind: PointKind, index: usize) ?EventClass {
        return switch (kind) {
            .binary_input => self.binary_inputs[index].class,
            .double_bit_input => self.double_bit_inputs[index].class,
            .binary_output_status => self.binary_outputs[index].class,
            .counter => self.counters[index].class,
            .frozen_counter => self.frozen_counters[index].class,
            .analog_input => self.analog_inputs[index].class,
            .analog_output_status => self.analog_outputs[index].class,
        };
    }

    fn setClass(self: Database, kind: PointKind, index: usize, class: ?EventClass) void {
        switch (kind) {
            .binary_input => self.binary_inputs[index].class = class,
            .double_bit_input => self.double_bit_inputs[index].class = class,
            .binary_output_status => self.binary_outputs[index].class = class,
            .counter => self.counters[index].class = class,
            .frozen_counter => self.frozen_counters[index].class = class,
            .analog_input => self.analog_inputs[index].class = class,
            .analog_output_status => self.analog_outputs[index].class = class,
        }
    }

    fn eventVariation(self: Database, kind: PointKind, index: usize) u8 {
        return switch (kind) {
            .binary_input => self.binary_inputs[index].event_variation,
            .double_bit_input => self.double_bit_inputs[index].event_variation,
            .binary_output_status => self.binary_outputs[index].event_variation,
            .counter => self.counters[index].event_variation,
            .frozen_counter => self.frozen_counters[index].event_variation,
            .analog_input => self.analog_inputs[index].event_variation,
            .analog_output_status => self.analog_outputs[index].event_variation,
        };
    }
};

/// Picks the `records.Value` shape that matches a float-valued point's
/// declared variation: the integer variations must carry an integer.
fn analogValue(value: f64, variation: u8) records.Value {
    return switch (variation) {
        5, 6 => .{ .analog_float = value },
        else => .{ .analog_int = std.math.lossyCast(i32, value) },
    };
}

// ── event buffer ────────────────────────────────────────────────────────────

/// One buffered event.
pub const Event = struct {
    kind: PointKind,
    index: u16,
    class: EventClass,
    variation: u8,
    flags: Flags,
    value: records.Value,
    time_ms: u48,
};

/// A bounded, caller-owned event ring shared by all three classes. Events are
/// reported oldest-first and retired only on CONFIRM. When it is full the
/// oldest event is dropped and `overflowed` latches, which becomes
/// IIN2.EVENT_BUFFER_OVERFLOW in every subsequent response until the buffer
/// drains (§11.2.2: the master is told it missed something).
pub const EventBuffer = struct {
    storage: []Event,
    head: usize = 0,
    len: usize = 0,
    /// How many of the oldest events are currently in flight, awaiting the
    /// master's application confirm.
    in_flight: usize = 0,
    overflowed: bool = false,

    pub fn init(storage: []Event) EventBuffer {
        return .{ .storage = storage };
    }

    pub fn at(self: *const EventBuffer, i: usize) *Event {
        return &self.storage[(self.head + i) % self.storage.len];
    }

    pub fn push(self: *EventBuffer, event: Event) void {
        if (self.storage.len == 0) {
            self.overflowed = true;
            return;
        }
        if (self.len == self.storage.len) {
            // Drop the oldest. If it was in flight the master will never get
            // it; the overflow bit is exactly how it finds out.
            self.head = (self.head + 1) % self.storage.len;
            self.len -= 1;
            if (self.in_flight > 0) self.in_flight -= 1;
            self.overflowed = true;
        }
        self.storage[(self.head + self.len) % self.storage.len] = event;
        self.len += 1;
    }

    pub fn countOf(self: *const EventBuffer, class: EventClass) usize {
        var n: usize = 0;
        for (0..self.len) |i| {
            if (self.at(i).class == class) n += 1;
        }
        return n;
    }

    pub fn isEmpty(self: *const EventBuffer) bool {
        return self.len == 0;
    }

    /// Retires the `in_flight` prefix — called when the master confirms.
    pub fn confirm(self: *EventBuffer) void {
        var remaining = self.in_flight;
        while (remaining > 0 and self.len > 0) : (remaining -= 1) {
            self.head = (self.head + 1) % self.storage.len;
            self.len -= 1;
        }
        self.in_flight = 0;
        if (self.len == 0) self.overflowed = false;
    }

    /// Un-marks the in-flight prefix — called when a confirm times out, so
    /// the same events are offered again on the next poll.
    pub fn releaseInFlight(self: *EventBuffer) void {
        self.in_flight = 0;
    }

    pub fn clear(self: *EventBuffer) void {
        self.head = 0;
        self.len = 0;
        self.in_flight = 0;
        self.overflowed = false;
    }
};

// ── command hook ────────────────────────────────────────────────────────────

pub const CommandKind = enum { select, operate, direct_operate };

/// A control request the outstation is about to honour. The hook may veto it
/// by returning any status other than `.success`; `.success` lets the
/// outstation apply it to the database.
pub const Command = union(enum) {
    crob: struct {
        index: u16,
        control: objects.g12.ControlCode,
        count: u8,
        on_time_ms: u32,
        off_time_ms: u32,
    },
    analog: struct {
        index: u16,
        value: f64,
    },
};

pub const CommandHook = struct {
    ctx: *anyopaque,
    onCommandFn: *const fn (ctx: *anyopaque, kind: CommandKind, command: Command) CommandStatus,

    pub fn ask(self: CommandHook, kind: CommandKind, command: Command) CommandStatus {
        return self.onCommandFn(self.ctx, kind, command);
    }
};

// ── configuration ───────────────────────────────────────────────────────────

pub const Config = struct {
    /// This outstation's data-link address.
    address: u16 = 1024,
    /// The master's data-link address.
    master_address: u16 = 1,

    /// Largest application fragment this outstation will emit. §4.1.2 fixes
    /// the *receive* minimum at 249; 2048 is the usual transmit default.
    max_tx_fragment: usize = 2048,

    /// How long a SELECT stays armed. Injected clock, so the caller decides
    /// what "now" means.
    select_timeout_ms: u64 = 10_000,

    /// Whether this outstation supports unsolicited responses at all. When
    /// false, ENABLE_UNSOLICITED is answered FUNC_NOT_SUPPORTED, which is the
    /// conformant way to say "do not expect any".
    unsolicited_supported: bool = false,

    /// Whether unsolicited reporting starts enabled once the master has
    /// cleared the restart IIN. Only meaningful when
    /// `unsolicited_supported` is true.
    unsolicited_enabled_at_start: bool = false,

    /// Reported by DELAY_MEASURE (g52v2): the outstation's own turnaround
    /// delay in milliseconds.
    delay_measure_ms: u16 = 0,

    /// Set IIN1.NEED_TIME at start-up and after every restart.
    need_time_at_start: bool = true,

    /// Honour COLD_RESTART / WARM_RESTART. Off by default: a simulator that
    /// silently accepts a restart teaches its operator the wrong lesson.
    allow_restart: bool = false,

    /// Time in milliseconds a restart says it needs, reported as g52v2.
    restart_delay_ms: u16 = 0,
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const Error = error{
    /// The caller's output buffer cannot hold even a minimal response header.
    BufferTooSmall,
};

// ── the reply ───────────────────────────────────────────────────────────────

pub const Reply = struct {
    /// The complete application response fragment.
    fragment: []u8,
    /// The outstation set CON: it wants an application CONFIRM before it
    /// retires the events this fragment carried, or before it sends the next
    /// fragment.
    confirm_requested: bool,
    /// FIN was clear: more fragments follow. Call `next` once the confirm
    /// arrives.
    more: bool,
    /// True when this is an unsolicited response rather than a solicited one.
    unsolicited: bool = false,
};

// ── the outstation ──────────────────────────────────────────────────────────

pub const Outstation = struct {
    config: Config,
    db: Database,
    events: EventBuffer,
    hook: ?CommandHook = null,

    // ── IIN state ──
    /// IIN1.7. Set at construction; only an explicit WRITE of g80v1 index 7
    /// clears it (§5.1.4.1 — a master that never clears it is misconfigured
    /// and should keep being told).
    restart: bool = true,
    /// IIN1.4.
    need_time: bool = false,
    /// IIN1.5 — some point is under local (not remote) control.
    local_control: bool = false,
    /// IIN1.6 — the device has an internal problem.
    device_trouble: bool = false,
    /// IIN2.5 — configuration is corrupt.
    config_corrupt: bool = false,

    // ── session state ──
    /// The sequence number of the last request we answered, for duplicate
    /// detection (§5.1.2: a repeat of the last request gets the same
    /// response, it is not re-executed).
    last_request_seq: ?u4 = null,
    /// The sequence number our next *unsolicited* response will carry.
    unsolicited_seq: u4 = 0,
    unsolicited_enabled: [3]bool = .{ false, false, false },
    /// An unsolicited response is out and unconfirmed.
    unsolicited_pending: bool = false,

    /// A SELECT that is armed and waiting for its OPERATE.
    select: ?Select = null,
    /// Set when `tick` drops a select because its arm window closed, so an
    /// OPERATE that arrives late can be answered TIMEOUT (§ command status 1)
    /// rather than the much less informative NO_SELECT.
    select_expired: bool = false,

    /// Where a multi-fragment response got to.
    cursor: ?Cursor = null,

    /// True while we are waiting for the master to confirm a response.
    awaiting_confirm: bool = false,

    /// IIN bits raised while parsing the current read request, carried into
    /// every fragment of its response.
    pending_extra_iin: Iin = .{},

    /// True while a multi-fragment response series is in progress, so the
    /// next fragment clears FIR.
    first_fragment_sent: bool = false,

    pub const Select = struct {
        /// The application sequence number the SELECT arrived with; the
        /// OPERATE must carry the next one (§5.1.5.1).
        seq: u4,
        armed_at_ms: u64,
        /// The object bytes the SELECT carried, verbatim. The OPERATE must
        /// present exactly the same ones.
        object_bytes: [max_select_bytes]u8,
        object_len: usize,
    };

    /// How many object bytes a SELECT may carry and still be matchable. A
    /// larger select is accepted and executed, but the OPERATE match falls
    /// back to "sequence number + length", which is what the spec's minimum
    /// requires anyway.
    pub const max_select_bytes = 128;

    /// A resumable position in a multi-fragment response.
    pub const Cursor = struct {
        /// The application sequence number this response series carries.
        seq: u4,
        /// Which read requests are still outstanding, in order.
        reads: [max_read_headers]ReadRequest,
        read_count: usize,
        read_pos: usize,
        /// Progress inside `reads[read_pos]`.
        item_pos: usize,
        /// How many events this response series has already emitted.
        events_sent: usize,
    };

    pub const max_read_headers = 8;

    /// One decoded READ object header, normalised.
    pub const ReadRequest = union(enum) {
        /// A class poll. Class 0 is the static scan.
        class: u2,
        statics: struct {
            kind: PointKind,
            /// 0 means "the variation each point declares".
            variation: u8,
            start: u32,
            stop: u32,
        },
        events: struct {
            kind: PointKind,
            variation: u8,
            /// 0 means "all of them".
            limit: u32,
        },
    };

    pub fn init(config: Config, db: Database, events: EventBuffer) Outstation {
        var self = Outstation{ .config = config, .db = db, .events = events };
        self.need_time = config.need_time_at_start;
        if (config.unsolicited_supported and config.unsolicited_enabled_at_start) {
            self.unsolicited_enabled = .{ true, true, true };
        }
        return self;
    }

    pub fn setCommandHook(self: *Outstation, hook: ?CommandHook) void {
        self.hook = hook;
    }

    // ── IIN ─────────────────────────────────────────────────────────────────

    /// The IIN bits this outstation currently reports, before any
    /// request-specific bits are merged in.
    pub fn iin(self: *const Outstation) Iin {
        return .{
            .device_restart = self.restart,
            .need_time = self.need_time,
            .local_control = self.local_control,
            .device_trouble = self.device_trouble,
            .config_corrupt = self.config_corrupt,
            .class_1_events = self.events.countOf(.class1) > 0,
            .class_2_events = self.events.countOf(.class2) > 0,
            .class_3_events = self.events.countOf(.class3) > 0,
            .event_buffer_overflow = self.events.overflowed,
        };
    }

    // ── driving the process image ───────────────────────────────────────────

    /// Applies a new value to a point and, if the point is assigned to an
    /// event class, buffers the corresponding event. This is how a simulator
    /// makes something happen: the value and the event stay consistent
    /// because they are set together.
    pub fn update(
        self: *Outstation,
        kind: PointKind,
        index: u16,
        value: records.Value,
        now_ms: u64,
    ) void {
        if (index >= self.db.count(kind)) return;
        switch (kind) {
            .binary_input => self.db.binary_inputs[index].value = value.binary,
            .double_bit_input => self.db.double_bit_inputs[index].value = value.double_bit,
            .binary_output_status => self.db.binary_outputs[index].value = value.binary,
            .counter => self.db.counters[index].value = value.counter,
            .frozen_counter => self.db.frozen_counters[index].value = value.counter,
            .analog_input => self.db.analog_inputs[index].value = valueAsFloat(value),
            .analog_output_status => self.db.analog_outputs[index].value = valueAsFloat(value),
        }
        self.reportChange(kind, index, now_ms);
    }

    /// Buffers an event for a point whose value the caller already changed
    /// directly in the database slice. A no-op when the point has no class.
    pub fn reportChange(self: *Outstation, kind: PointKind, index: u16, now_ms: u64) void {
        if (index >= self.db.count(kind)) return;
        const class = self.db.classOf(kind, index) orelse return;
        self.events.push(.{
            .kind = kind,
            .index = index,
            .class = class,
            .variation = self.db.eventVariation(kind, index),
            .flags = self.db.flagsOf(kind, index),
            .value = self.eventValue(kind, index),
            .time_ms = @truncate(now_ms),
        });
    }

    fn eventValue(self: *const Outstation, kind: PointKind, index: usize) records.Value {
        return switch (kind) {
            .binary_input => .{ .binary = self.db.binary_inputs[index].value },
            .double_bit_input => .{ .double_bit = self.db.double_bit_inputs[index].value },
            .binary_output_status => .{ .binary = self.db.binary_outputs[index].value },
            .counter => .{ .counter = self.db.counters[index].value },
            .frozen_counter => .{ .counter = self.db.frozen_counters[index].value },
            .analog_input => analogValue(
                self.db.analog_inputs[index].value,
                self.db.analog_inputs[index].event_variation,
            ),
            .analog_output_status => analogValue(
                self.db.analog_outputs[index].value,
                self.db.analog_outputs[index].event_variation,
            ),
        };
    }

    // ── timers ──────────────────────────────────────────────────────────────

    /// Expires the select-before-operate arm window. Call it whenever the
    /// caller's clock moves; it never blocks and owns no timer of its own.
    pub fn tick(self: *Outstation, now_ms: u64) void {
        if (self.select) |s| {
            if (now_ms -% s.armed_at_ms >= self.config.select_timeout_ms) {
                self.select = null;
                self.select_expired = true;
            }
        }
    }

    /// The absolute deadline the caller should wake us at, if any.
    pub fn nextDeadline(self: *const Outstation) ?u64 {
        const s = self.select orelse return null;
        return s.armed_at_ms + self.config.select_timeout_ms;
    }

    /// Tells the outstation the confirm it was waiting for never came. The
    /// events it had in flight go back on the queue so the next poll offers
    /// them again.
    pub fn confirmTimedOut(self: *Outstation) void {
        self.events.releaseInFlight();
        self.awaiting_confirm = false;
        self.unsolicited_pending = false;
        self.cursor = null;
    }

    // ── the request entry point ─────────────────────────────────────────────

    /// Handles one complete application request fragment and writes one
    /// complete application response fragment into `out`.
    ///
    /// Returns `null` when nothing should be sent: a CONFIRM (which is itself
    /// a response to us), or a request that explicitly asks for no reply.
    /// `out` should be at least `config.max_tx_fragment` bytes; anything
    /// smaller simply caps the fragment size.
    pub fn handle(self: *Outstation, request: []const u8, now_ms: u64, out: []u8) Error!?Reply {
        self.tick(now_ms);
        if (out.len < application.response_header_len + 2) return error.BufferTooSmall;

        const decoded = application.decodeRequestHeader(request) catch
            return try self.errorResponse(0, .{ .parameter_error = true }, out);
        const control = decoded.header.control;
        const seq = control.seq;
        const function = decoded.header.function;
        const body = decoded.rest;

        // A CONFIRM is not a request: it retires whatever was in flight.
        if (function == .confirm) {
            self.onConfirm(control.uns);
            return null;
        }

        // A request that is not the first *and* last segment of its fragment
        // is a transport-layer error we cannot act on. §5.1.1: the request
        // must be a single application fragment.
        if (!control.fir or !control.fin) {
            return try self.errorResponse(seq, .{ .parameter_error = true }, out);
        }

        // Any new request abandons an unfinished multi-fragment response.
        self.cursor = null;
        self.awaiting_confirm = false;
        self.last_request_seq = seq;

        return switch (function) {
            .read => try self.doRead(seq, body, now_ms, out),
            .write => try self.doWrite(seq, body, now_ms, out),
            .select => try self.doCommand(.select, seq, body, now_ms, out, true),
            .operate => try self.doCommand(.operate, seq, body, now_ms, out, true),
            .direct_operate => try self.doCommand(.direct_operate, seq, body, now_ms, out, true),
            .direct_operate_no_ack => blk: {
                _ = try self.doCommand(.direct_operate, seq, body, now_ms, out, false);
                break :blk null;
            },
            .cold_restart => try self.doRestart(seq, true, out),
            .warm_restart => try self.doRestart(seq, false, out),
            .delay_measure => try self.doDelayMeasure(seq, out),
            .enable_unsolicited => try self.doUnsolicitedControl(seq, body, true, out),
            .disable_unsolicited => try self.doUnsolicitedControl(seq, body, false, out),
            .immediate_freeze => try self.doFreeze(seq, body, now_ms, false, true, out),
            .immediate_freeze_no_ack => blk: {
                _ = try self.doFreeze(seq, body, now_ms, false, false, out);
                break :blk null;
            },
            .freeze_clear => try self.doFreeze(seq, body, now_ms, true, true, out),
            .freeze_clear_no_ack => blk: {
                _ = try self.doFreeze(seq, body, now_ms, true, false, out);
                break :blk null;
            },
            .assign_class => try self.doAssignClass(seq, body, out),
            .record_current_time => try self.emptyResponse(seq, .{}, out),
            else => try self.errorResponse(seq, .{ .func_not_supported = true }, out),
        };
    }

    /// Produces the next fragment of a multi-fragment response, after the
    /// master has confirmed the previous one. Returns `null` when the
    /// response is complete.
    pub fn next(self: *Outstation, now_ms: u64, out: []u8) Error!?Reply {
        _ = now_ms;
        if (self.cursor == null) return null;
        return try self.buildReadResponse(out);
    }

    /// Builds an unsolicited response carrying the buffered events of the
    /// enabled classes, or `null` when there is nothing to report (or
    /// unsolicited reporting is off, or one is already unconfirmed).
    ///
    /// The *retry* policy is the caller's: this function only builds the
    /// fragment. `confirmTimedOut` puts the events back.
    pub fn unsolicited(self: *Outstation, now_ms: u64, out: []u8) Error!?Reply {
        _ = now_ms;
        if (!self.config.unsolicited_supported) return null;
        if (self.unsolicited_pending or self.restart) return null;
        if (self.events.len == self.events.in_flight) return null;

        // Is anything pending in an enabled class?
        var any = false;
        for (self.events.in_flight..self.events.len) |i| {
            const cls = self.events.at(i).class;
            if (self.unsolicited_enabled[@as(usize, @intFromEnum(cls)) - 1]) any = true;
        }
        if (!any) return null;

        const seq = self.unsolicited_seq;
        var pos = (try self.writeHeader(seq, .unsolicited_response, self.iin(), true, out)).len;
        const emitted = self.emitEvents(out, &pos, null, 0, self.unsolicited_enabled, null);
        if (emitted == 0) return null;
        self.events.in_flight += emitted;
        self.unsolicited_seq +%= 1;
        self.unsolicited_pending = true;
        self.awaiting_confirm = true;

        // FIR + FIN + CON + UNS.
        out[0] = (application.AppControl{
            .fir = true,
            .fin = true,
            .con = true,
            .uns = true,
            .seq = seq,
        }).toByte();
        return .{ .fragment = out[0..pos], .confirm_requested = true, .more = false, .unsolicited = true };
    }

    fn onConfirm(self: *Outstation, uns: bool) void {
        if (uns) self.unsolicited_pending = false;
        self.events.confirm();
        self.awaiting_confirm = false;
    }

    // ── response scaffolding ────────────────────────────────────────────────

    fn writeHeader(
        self: *Outstation,
        seq: u4,
        function: FunctionCode,
        bits: Iin,
        con: bool,
        out: []u8,
    ) Error![]u8 {
        _ = self;
        return application.encodeResponseHeader(.{
            .control = .{ .fir = true, .fin = true, .con = con, .seq = seq },
            .function = function,
            .iin = bits,
        }, out) catch return error.BufferTooSmall;
    }

    fn mergeIin(self: *const Outstation, extra: Iin) Iin {
        var bits = self.iin();
        if (extra.func_not_supported) bits.func_not_supported = true;
        if (extra.object_unknown) bits.object_unknown = true;
        if (extra.parameter_error) bits.parameter_error = true;
        if (extra.already_executing) bits.already_executing = true;
        return bits;
    }

    fn emptyResponse(self: *Outstation, seq: u4, extra: Iin, out: []u8) Error!?Reply {
        const bytes = try self.writeHeader(seq, .response, self.mergeIin(extra), false, out);
        return .{ .fragment = bytes, .confirm_requested = false, .more = false };
    }

    fn errorResponse(self: *Outstation, seq: u4, extra: Iin, out: []u8) Error!?Reply {
        return try self.emptyResponse(seq, extra, out);
    }

    // ── READ ────────────────────────────────────────────────────────────────

    fn doRead(self: *Outstation, seq: u4, body: []const u8, now_ms: u64, out: []u8) Error!?Reply {
        _ = now_ms;
        var cursor = Cursor{
            .seq = seq,
            .reads = undefined,
            .read_count = 0,
            .read_pos = 0,
            .item_pos = 0,
            .events_sent = 0,
        };
        var extra = Iin{};

        var rest = body;
        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            rest = rest[hdr.consumed..];
            if (cursor.read_count == max_read_headers) {
                extra.parameter_error = true;
                break;
            }
            const parsed = self.parseReadHeader(hdr.header) catch |err| {
                switch (err) {
                    error.UnknownObject => extra.object_unknown = true,
                    error.BadParameter => extra.parameter_error = true,
                }
                continue;
            };
            cursor.reads[cursor.read_count] = parsed;
            cursor.read_count += 1;
        }

        if (cursor.read_count == 0) {
            return try self.emptyResponse(seq, extra, out);
        }

        self.cursor = cursor;
        self.pending_extra_iin = extra;
        return try self.buildReadResponse(out);
    }

    const ParseError = error{ UnknownObject, BadParameter };

    fn parseReadHeader(self: *const Outstation, header: objects.ObjectHeader) ParseError!ReadRequest {
        if (header.group == 60) {
            return switch (header.variation) {
                1 => .{ .class = 0 },
                2 => .{ .class = 1 },
                3 => .{ .class = 2 },
                4 => .{ .class = 3 },
                else => error.UnknownObject,
            };
        }

        if (records.PointKind.fromEventGroup(header.group)) |kind| {
            if (header.variation != 0 and records.layoutOf(header.group, header.variation) == null) {
                return error.UnknownObject;
            }
            const limit: u32 = switch (header.range) {
                .all_values => 0,
                .count => |c| c,
                .start_stop => return error.BadParameter, // events have no static index range
            };
            return .{ .events = .{ .kind = kind, .variation = header.variation, .limit = limit } };
        }

        if (records.PointKind.fromStaticGroup(header.group)) |kind| {
            if (header.variation != 0 and records.layoutOf(header.group, header.variation) == null) {
                return error.UnknownObject;
            }
            const n = self.db.count(kind);
            if (n == 0) return error.UnknownObject;
            const start: u32, const stop: u32 = switch (header.range) {
                .all_values => .{ 0, @intCast(n - 1) },
                .start_stop => |r| blk: {
                    if (r.stop < r.start) return error.BadParameter;
                    if (r.stop >= n) return error.BadParameter;
                    break :blk .{ r.start, r.stop };
                },
                .count => |c| blk: {
                    if (c == 0 or c > n) return error.BadParameter;
                    break :blk .{ 0, c - 1 };
                },
            };
            return .{ .statics = .{ .kind = kind, .variation = header.variation, .start = start, .stop = stop } };
        }

        return error.UnknownObject;
    }

    /// Emits as much of the pending read as fits in one fragment.
    fn buildReadResponse(self: *Outstation, out: []u8) Error!?Reply {
        var cursor = self.cursor.?;
        const limit = @min(out.len, self.config.max_tx_fragment);
        if (limit < application.response_header_len + 4) return error.BufferTooSmall;

        var pos: usize = application.response_header_len;
        var complete = true;

        while (cursor.read_pos < cursor.read_count) {
            const request = cursor.reads[cursor.read_pos];
            const done = switch (request) {
                .class => |c| self.emitClass(c, out[0..limit], &pos, &cursor),
                .statics => |s| self.emitStatics(
                    s.kind,
                    s.variation,
                    s.start,
                    s.stop,
                    out[0..limit],
                    &pos,
                    &cursor.item_pos,
                ),
                .events => |e| blk: {
                    const before = cursor.events_sent;
                    const emitted = self.emitEvents(
                        out[0..limit],
                        &pos,
                        e.kind,
                        before,
                        .{ true, true, true },
                        if (e.limit == 0) null else e.limit,
                    );
                    cursor.events_sent = before + emitted;
                    const total = self.pendingEventCount(e.kind);
                    const want = if (e.limit == 0) total else @min(e.limit, total);
                    break :blk cursor.events_sent >= want;
                },
            };
            if (!done) {
                complete = false;
                break;
            }
            cursor.read_pos += 1;
            cursor.item_pos = 0;
        }

        const carries_events = cursor.events_sent > 0;
        // A fragment that is not the last one always asks for a confirm (the
        // master's confirm is what releases the next one), and so does any
        // fragment carrying events (the confirm is what retires them).
        const con = !complete or carries_events;
        const bits = self.mergeIin(self.pending_extra_iin);
        _ = application.encodeResponseHeader(.{
            .control = .{
                // FIR is set only on the first fragment of the series.
                .fir = !self.first_fragment_sent,
                .fin = complete,
                .con = con,
                .seq = cursor.seq,
            },
            .function = .response,
            .iin = bits,
        }, out) catch return error.BufferTooSmall;
        self.first_fragment_sent = !complete;

        if (carries_events) self.events.in_flight = cursor.events_sent;
        if (complete) {
            self.cursor = null;
            self.first_fragment_sent = false;
        } else {
            // §5.1.6.2: each subsequent fragment of a multi-fragment response
            // carries the *next* sequence number, and the master confirms
            // each one with that number. Reusing the request's sequence for
            // every fragment makes a real master log "Response with bad
            // sequence" and stall -- which is what opendnp3's master-demo did
            // to the first draft of this code.
            cursor.seq +%= 1;
            self.cursor = cursor;
        }
        self.awaiting_confirm = con;

        return .{ .fragment = out[0..pos], .confirm_requested = con, .more = !complete };
    }

    fn pendingEventCount(self: *const Outstation, kind: ?PointKind) usize {
        var n: usize = 0;
        for (0..self.events.len) |i| {
            const ev = self.events.at(i);
            if (kind == null or ev.kind == kind.?) n += 1;
        }
        return n;
    }

    /// A class poll: class 0 walks every static point; classes 1-3 drain the
    /// event buffer for that class.
    fn emitClass(self: *Outstation, class: u2, out: []u8, pos: *usize, cursor: *Cursor) bool {
        if (class == 0) {
            // Class 0 is a full static scan across all seven point types.
            const kinds = std.enums.values(PointKind);
            while (cursor.item_pos < kinds.len * scan_stride) {
                const kind_index = cursor.item_pos / scan_stride;
                const kind = kinds[kind_index];
                const n = self.db.count(kind);
                var within = cursor.item_pos % scan_stride;
                if (n == 0) {
                    cursor.item_pos = (kind_index + 1) * scan_stride;
                    continue;
                }
                const done = self.emitStatics(kind, 0, 0, @intCast(n - 1), out, pos, &within);
                cursor.item_pos = kind_index * scan_stride + within;
                if (!done) return false;
                cursor.item_pos = (kind_index + 1) * scan_stride;
            }
            return true;
        }

        var enabled = [3]bool{ false, false, false };
        enabled[class - 1] = true;
        const before = cursor.events_sent;
        const emitted = self.emitEvents(out, pos, null, before, enabled, null);
        cursor.events_sent = before + emitted;
        // Everything in this class that was pending has now been offered.
        var pending: usize = 0;
        for (0..self.events.len) |i| {
            if (@intFromEnum(self.events.at(i).class) == class) pending += 1;
        }
        return cursor.events_sent >= pending;
    }

    /// Stride reserved per point kind inside a class-0 cursor. It has to
    /// exceed any realistic point count for one kind; the cursor stores
    /// `kind_index * scan_stride + point_index`.
    const scan_stride: usize = 1 << 32;

    /// Emits static objects for `kind` in `[start, stop]`, resuming at
    /// `item_pos`. Returns true when the whole range fitted.
    fn emitStatics(
        self: *Outstation,
        kind: PointKind,
        variation: u8,
        start: u32,
        stop: u32,
        out: []u8,
        pos: *usize,
        item_pos: *usize,
    ) bool {
        const total = stop - start + 1;
        while (item_pos.* < total) {
            const first: u32 = start + @as(u32, @intCast(item_pos.*));
            // Every point in a run must share one variation, since one object
            // header covers the whole run. Start a new header whenever the
            // declared variation changes.
            const var_used = if (variation != 0)
                variation
            else
                self.db.staticVariation(kind, first);
            const layout = records.layoutOf(kind.staticGroup(), var_used) orelse {
                // A point declaring a variation we cannot encode: skip it
                // rather than emit garbage.
                item_pos.* += 1;
                continue;
            };

            // How many consecutive points share this variation?
            var run: u32 = 1;
            while (first + run <= stop) : (run += 1) {
                const next_var = if (variation != 0)
                    variation
                else
                    self.db.staticVariation(kind, first + run);
                if (next_var != var_used) break;
            }

            const emitted = self.emitRun(kind, var_used, layout, first, run, out, pos);
            if (emitted == 0) return false;
            item_pos.* += emitted;
            if (emitted < run) return false;
        }
        return true;
    }

    /// Writes one object header plus as many of `run` points as fit,
    /// returning how many points it managed.
    fn emitRun(
        self: *Outstation,
        kind: PointKind,
        variation: u8,
        layout: records.Layout,
        first: u32,
        run: u32,
        out: []u8,
        pos: *usize,
    ) u32 {
        const wide = first + run - 1 > 0xFF;
        const header_len: usize = if (wide) 7 else 5;
        if (pos.* + header_len + 1 > out.len) return 0;

        // How many points fit after the header?
        const space = out.len - pos.* - header_len;
        var fit: u32 = undefined;
        if (layout.isPacked()) {
            const per = if (layout.value == .packed_bit) @as(usize, 8) else 4;
            fit = @intCast(@min(@as(usize, run), space * per));
            if (fit == 0) return 0;
            // Recompute the byte count for the points that fit.
        } else {
            const each = layout.wireLen().?;
            fit = @intCast(@min(@as(usize, run), space / each));
            if (fit == 0) return 0;
        }

        const last = first + fit - 1;
        const header = objects.ObjectHeader{
            .group = kind.staticGroup(),
            .variation = variation,
            .qualifier = .{
                .prefix_code = .none,
                .range_code = if (wide) .start_stop_2b else .start_stop_1b,
            },
            .range = .{ .start_stop = .{ .start = first, .stop = last } },
        };
        const hdr = objects.encodeObjectHeader(header, out[pos.*..]) catch return 0;
        pos.* += hdr.len;

        if (layout.isPacked()) {
            const nbytes = if (layout.value == .packed_bit)
                records.packedBitBytes(fit)
            else
                records.packedDoubleBitBytes(fit);
            @memset(out[pos.*..][0..nbytes], 0);
            for (0..fit) |i| {
                const value = self.db.valueOf(kind, first + i);
                switch (layout.value) {
                    .packed_bit => records.setPackedBit(out[pos.*..], i, value.binary),
                    .packed_dbit => records.setPackedDoubleBit(out[pos.*..], i, value.double_bit),
                    else => unreachable,
                }
            }
            pos.* += nbytes;
        } else {
            for (0..fit) |i| {
                const idx = first + i;
                const bytes = records.encode(
                    layout,
                    self.db.flagsOf(kind, idx),
                    self.db.valueOf(kind, idx),
                    0,
                    0,
                    out[pos.*..],
                ) catch return @intCast(i);
                pos.* += bytes.len;
            }
        }
        return fit;
    }

    /// Emits buffered events (oldest first, skipping the first `skip` of the
    /// matching set) as long as they fit. Returns how many it wrote.
    fn emitEvents(
        self: *Outstation,
        out: []u8,
        pos: *usize,
        kind_filter: ?PointKind,
        skip: usize,
        classes: [3]bool,
        limit: ?usize,
    ) usize {
        var seen: usize = 0;
        var written: usize = 0;
        var i: usize = 0;
        while (i < self.events.len) : (i += 1) {
            const ev = self.events.at(i);
            if (!classes[@as(usize, @intFromEnum(ev.class)) - 1]) continue;
            if (kind_filter) |k| {
                if (ev.kind != k) continue;
            }
            seen += 1;
            if (seen <= skip) continue;
            if (limit) |max| {
                if (skip + written >= max) break;
            }

            const group = ev.kind.eventGroup();
            const layout = records.layoutOf(group, ev.variation) orelse continue;
            if (layout.isPacked()) continue; // no packed event variations exist

            const wide = ev.index > 0xFF;
            const header_len: usize = if (wide) 6 else 4; // g/v/qual + count + prefix
            const each = layout.wireLen().? + @as(usize, if (wide) 2 else 1);
            if (pos.* + header_len + each > out.len) break;

            const header = objects.ObjectHeader{
                .group = group,
                .variation = ev.variation,
                .qualifier = .{
                    .prefix_code = if (wide) .index_2b else .index_1b,
                    .range_code = if (wide) .count_2b else .count_1b,
                },
                .range = .{ .count = 1 },
            };
            const hdr = objects.encodeObjectHeader(header, out[pos.*..]) catch break;
            pos.* += hdr.len;
            if (wide) {
                std.mem.writeInt(u16, out[pos.*..][0..2], ev.index, .little);
                pos.* += 2;
            } else {
                out[pos.*] = @intCast(ev.index);
                pos.* += 1;
            }
            const bytes = records.encode(layout, ev.flags, ev.value, ev.time_ms, 0, out[pos.*..]) catch break;
            pos.* += bytes.len;
            written += 1;
        }
        return written;
    }

    // ── WRITE ───────────────────────────────────────────────────────────────

    fn doWrite(self: *Outstation, seq: u4, body: []const u8, now_ms: u64, out: []u8) Error!?Reply {
        _ = now_ms;
        var extra = Iin{};
        var rest = body;
        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            rest = rest[hdr.consumed..];
            const h = hdr.header;

            if (h.group == 80 and h.variation == 1) {
                // Write of Internal Indications: the only writable bit is
                // IIN1.7 (device restart), and only to 0 (§5.1.4.1).
                if (rest.len < 1) {
                    extra.parameter_error = true;
                    break;
                }
                // One packed bit for index 7 (start-stop 7..7).
                const bit = rest[0] & 0x01;
                if (bit == 0) self.restart = false else extra.parameter_error = true;
                rest = rest[1..];
                continue;
            }

            if (h.group == 50 and (h.variation == 1 or h.variation == 3)) {
                // Time and date: the master is answering our NEED_TIME.
                if (rest.len < objects.g50.V1.wire_len) {
                    extra.parameter_error = true;
                    break;
                }
                _ = objects.g50.V1.decode(rest) catch {
                    extra.parameter_error = true;
                    break;
                };
                self.need_time = false;
                rest = rest[objects.g50.V1.wire_len..];
                continue;
            }

            // Anything else is not writable on this outstation.
            extra.object_unknown = true;
            break;
        }
        return try self.emptyResponse(seq, extra, out);
    }

    // ── SELECT / OPERATE / DIRECT_OPERATE ──────────────────────────────────

    fn doCommand(
        self: *Outstation,
        kind: CommandKind,
        seq: u4,
        body: []const u8,
        now_ms: u64,
        out: []u8,
        want_reply: bool,
    ) Error!?Reply {
        var extra = Iin{};
        var pos: usize = application.response_header_len;
        if (out.len < pos) return error.BufferTooSmall;

        // For OPERATE, the select must be armed, unexpired, for the previous
        // sequence number, and carry byte-identical objects.
        var select_status: ?CommandStatus = null;
        if (kind == .operate) {
            if (self.select) |s| {
                if (now_ms -% s.armed_at_ms >= self.config.select_timeout_ms) {
                    select_status = .timeout;
                } else if (s.seq +% 1 != seq) {
                    select_status = .no_select;
                } else if (s.object_len != body.len or
                    !std.mem.eql(u8, s.object_bytes[0..s.object_len], body))
                {
                    select_status = .no_select;
                }
            } else {
                select_status = if (self.select_expired) .timeout else .no_select;
            }
        }

        var rest = body;
        var any_object = false;
        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            const header_bytes = rest[0..hdr.consumed];
            rest = rest[hdr.consumed..];
            const h = hdr.header;

            const count: u32 = switch (h.range) {
                .count => |c| c,
                .start_stop => |r| if (r.stop >= r.start) r.stop - r.start + 1 else {
                    extra.parameter_error = true;
                    break;
                },
                .all_values => {
                    extra.parameter_error = true;
                    break;
                },
            };
            const prefix_len: usize = switch (h.qualifier.prefix_code) {
                .none => 0,
                .index_1b => 1,
                .index_2b => 2,
                .index_4b => 4,
                else => {
                    extra.parameter_error = true;
                    break;
                },
            };

            const record_len: usize = switch (h.group) {
                12 => if (h.variation == 1) objects.g12.V1.wire_len else {
                    extra.object_unknown = true;
                    break;
                },
                41 => switch (h.variation) {
                    1 => objects.g41.V1.wire_len,
                    2 => objects.g41.V2.wire_len,
                    3 => objects.g41.V3.wire_len,
                    4 => 9, // f64 + status
                    else => {
                        extra.object_unknown = true;
                        break;
                    },
                },
                else => {
                    extra.object_unknown = true;
                    break;
                },
            };

            // Echo the request's own object header, then each object with a
            // status byte replacing the request's.
            if (pos + header_bytes.len > out.len) return error.BufferTooSmall;
            @memcpy(out[pos..][0..header_bytes.len], header_bytes);
            pos += header_bytes.len;

            var i: u32 = 0;
            while (i < count) : (i += 1) {
                if (rest.len < prefix_len + record_len) {
                    extra.parameter_error = true;
                    break;
                }
                const index: u16 = switch (prefix_len) {
                    0 => @intCast(switch (h.range) {
                        .start_stop => |r| r.start + i,
                        else => i,
                    }),
                    1 => rest[0],
                    2 => std.mem.readInt(u16, rest[0..2], .little),
                    else => @truncate(std.mem.readInt(u32, rest[0..4], .little)),
                };
                const object = rest[prefix_len..][0..record_len];
                rest = rest[prefix_len + record_len ..];
                any_object = true;

                const status = select_status orelse self.executeCommand(kind, h, index, object, now_ms);

                if (pos + prefix_len + record_len > out.len) return error.BufferTooSmall;
                if (prefix_len > 0) {
                    @memcpy(out[pos..][0..prefix_len], (rest.ptr - record_len - prefix_len)[0..prefix_len]);
                    pos += prefix_len;
                }
                @memcpy(out[pos..][0..record_len], object);
                out[pos + record_len - 1] = @intFromEnum(status);
                pos += record_len;
            }
        }

        if (!any_object) extra.parameter_error = true;

        // A successful SELECT arms the operate window.
        if (kind == .select and !extra.parameter_error and !extra.object_unknown) {
            var s = Select{ .seq = seq, .armed_at_ms = now_ms, .object_bytes = undefined, .object_len = 0 };
            if (body.len <= max_select_bytes) {
                @memcpy(s.object_bytes[0..body.len], body);
                s.object_len = body.len;
                self.select = s;
                self.select_expired = false;
            } else {
                extra.parameter_error = true;
            }
        }
        if (kind == .operate) {
            self.select = null;
            self.select_expired = false;
        }

        _ = application.encodeResponseHeader(.{
            .control = .{ .fir = true, .fin = true, .seq = seq },
            .function = .response,
            .iin = self.mergeIin(extra),
        }, out) catch return error.BufferTooSmall;

        if (!want_reply) return null;
        return .{ .fragment = out[0..pos], .confirm_requested = false, .more = false };
    }

    fn executeCommand(
        self: *Outstation,
        kind: CommandKind,
        header: objects.ObjectHeader,
        index: u16,
        object: []const u8,
        now_ms: u64,
    ) CommandStatus {
        if (header.group == 12) {
            const crob = objects.g12.V1.decode(object) catch return .format_error;
            if (index >= self.db.binary_outputs.len) return .not_supported;
            if (!self.db.binary_outputs[index].supports_commands) return .not_supported;

            const command = Command{ .crob = .{
                .index = index,
                .control = crob.control_code,
                .count = crob.count,
                .on_time_ms = crob.on_time_ms,
                .off_time_ms = crob.off_time_ms,
            } };
            if (self.hook) |h| {
                const verdict = h.ask(kind, command);
                if (verdict != .success) return verdict;
            }
            if (kind == .select) return .success; // a select changes nothing

            const new_value: ?bool = switch (crob.control_code.op_type) {
                .latch_on => true,
                .latch_off => false,
                .pulse_on => switch (crob.control_code.tcc) {
                    .close => true,
                    .trip => false,
                    else => true,
                },
                .pulse_off => switch (crob.control_code.tcc) {
                    .close => false,
                    .trip => true,
                    else => false,
                },
                .nul => null,
                _ => return .not_supported,
            };
            if (new_value) |v| {
                self.db.binary_outputs[index].value = v;
                self.reportChange(.binary_output_status, index, now_ms);
            }
            return .success;
        }

        if (header.group == 41) {
            const value: f64 = switch (header.variation) {
                1 => @floatFromInt(std.mem.readInt(i32, object[0..4], .little)),
                2 => @floatFromInt(std.mem.readInt(i16, object[0..2], .little)),
                3 => @as(f32, @bitCast(std.mem.readInt(u32, object[0..4], .little))),
                4 => @bitCast(std.mem.readInt(u64, object[0..8], .little)),
                else => return .not_supported,
            };
            if (index >= self.db.analog_outputs.len) return .not_supported;
            const point = &self.db.analog_outputs[index];
            if (!point.supports_commands) return .not_supported;
            if (value < point.min or value > point.max) return .out_of_range;

            if (self.hook) |h| {
                const verdict = h.ask(kind, .{ .analog = .{ .index = index, .value = value } });
                if (verdict != .success) return verdict;
            }
            if (kind == .select) return .success;
            point.value = value;
            self.reportChange(.analog_output_status, index, now_ms);
            return .success;
        }

        return .not_supported;
    }

    // ── restart / delay measure / unsolicited control / freeze / class ─────

    fn doRestart(self: *Outstation, seq: u4, cold: bool, out: []u8) Error!?Reply {
        if (!self.config.allow_restart) {
            return try self.errorResponse(seq, .{ .func_not_supported = true }, out);
        }
        // A restart resets everything a restart resets.
        self.restart = true;
        self.need_time = self.config.need_time_at_start;
        self.select = null;
        self.cursor = null;
        self.events.clear();
        self.unsolicited_pending = false;
        if (cold) self.unsolicited_enabled = .{ false, false, false };

        // The response carries g52v2 (time delay, fine) with the restart time.
        var pos = (try self.writeHeader(seq, .response, self.iin(), false, out)).len;
        const header = objects.ObjectHeader{
            .group = 52,
            .variation = 2,
            .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
            .range = .{ .count = 1 },
        };
        const hdr = objects.encodeObjectHeader(header, out[pos..]) catch return error.BufferTooSmall;
        pos += hdr.len;
        if (pos + 2 > out.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[pos..][0..2], self.config.restart_delay_ms, .little);
        pos += 2;
        return .{ .fragment = out[0..pos], .confirm_requested = false, .more = false };
    }

    fn doDelayMeasure(self: *Outstation, seq: u4, out: []u8) Error!?Reply {
        var pos = (try self.writeHeader(seq, .response, self.iin(), false, out)).len;
        const header = objects.ObjectHeader{
            .group = 52,
            .variation = 2,
            .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
            .range = .{ .count = 1 },
        };
        const hdr = objects.encodeObjectHeader(header, out[pos..]) catch return error.BufferTooSmall;
        pos += hdr.len;
        if (pos + 2 > out.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[pos..][0..2], self.config.delay_measure_ms, .little);
        pos += 2;
        return .{ .fragment = out[0..pos], .confirm_requested = false, .more = false };
    }

    fn doUnsolicitedControl(self: *Outstation, seq: u4, body: []const u8, enable: bool, out: []u8) Error!?Reply {
        if (!self.config.unsolicited_supported) {
            return try self.errorResponse(seq, .{ .func_not_supported = true }, out);
        }
        var extra = Iin{};
        var rest = body;
        var touched = false;
        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            rest = rest[hdr.consumed..];
            if (hdr.header.group != 60) {
                extra.object_unknown = true;
                break;
            }
            switch (hdr.header.variation) {
                2, 3, 4 => {
                    self.unsolicited_enabled[hdr.header.variation - 2] = enable;
                    touched = true;
                },
                else => extra.parameter_error = true,
            }
        }
        if (!touched and !extra.parameter_error and !extra.object_unknown) extra.parameter_error = true;
        return try self.emptyResponse(seq, extra, out);
    }

    fn doFreeze(
        self: *Outstation,
        seq: u4,
        body: []const u8,
        now_ms: u64,
        clear: bool,
        want_reply: bool,
        out: []u8,
    ) Error!?Reply {
        var extra = Iin{};
        var rest = body;
        // No object headers at all means "freeze everything".
        if (rest.len == 0) {
            self.freezeRange(0, self.db.counters.len, clear, now_ms);
        }
        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            rest = rest[hdr.consumed..];
            if (hdr.header.group != 20) {
                extra.object_unknown = true;
                break;
            }
            switch (hdr.header.range) {
                .all_values => {
                    self.freezeRange(0, self.db.counters.len, clear, now_ms);
                },
                .start_stop => |r| {
                    if (r.stop < r.start or r.stop >= self.db.counters.len) {
                        extra.parameter_error = true;
                    } else {
                        self.freezeRange(r.start, r.stop + 1, clear, now_ms);
                    }
                },
                .count => |c| {
                    if (c > self.db.counters.len) {
                        extra.parameter_error = true;
                    } else {
                        self.freezeRange(0, c, clear, now_ms);
                    }
                },
            }
        }
        if (!want_reply) return null;
        return try self.emptyResponse(seq, extra, out);
    }

    fn freezeRange(self: *Outstation, start: usize, end: usize, clear: bool, now_ms: u64) void {
        const stop = @min(end, @min(self.db.counters.len, self.db.frozen_counters.len));
        var i = start;
        while (i < stop) : (i += 1) {
            self.db.frozen_counters[i].value = self.db.counters[i].value;
            self.db.frozen_counters[i].flags = self.db.counters[i].flags;
            self.reportChange(.frozen_counter, @intCast(i), now_ms);
            if (clear) self.db.counters[i].value = 0;
        }
    }

    fn doAssignClass(self: *Outstation, seq: u4, body: []const u8, out: []u8) Error!?Reply {
        var extra = Iin{};
        var rest = body;
        var class: ?EventClass = null;
        var have_class = false;

        while (rest.len > 0) {
            const hdr = objects.decodeObjectHeader(rest) catch {
                extra.parameter_error = true;
                break;
            };
            rest = rest[hdr.consumed..];
            const h = hdr.header;

            if (h.group == 60) {
                class = switch (h.variation) {
                    1 => null, // class 0 = "no events"
                    2 => .class1,
                    3 => .class2,
                    4 => .class3,
                    else => {
                        extra.parameter_error = true;
                        break;
                    },
                };
                have_class = true;
                continue;
            }

            if (!have_class) {
                extra.parameter_error = true;
                break;
            }
            const kind = records.PointKind.fromStaticGroup(h.group) orelse {
                extra.object_unknown = true;
                break;
            };
            const n = self.db.count(kind);
            const start: usize, const stop: usize = switch (h.range) {
                .all_values => .{ 0, if (n == 0) 0 else n - 1 },
                .start_stop => |r| .{ r.start, r.stop },
                .count => |c| .{ 0, if (c == 0) 0 else c - 1 },
            };
            if (n == 0 or stop >= n or stop < start) {
                extra.parameter_error = true;
                break;
            }
            for (start..stop + 1) |i| self.db.setClass(kind, i, class);
        }
        return try self.emptyResponse(seq, extra, out);
    }
};

fn valueAsFloat(value: records.Value) f64 {
    return switch (value) {
        .analog_float => |f| f,
        .analog_int => |i| @floatFromInt(i),
        .counter => |c| @floatFromInt(c),
        .binary => |b| @floatFromInt(@intFromBool(b)),
        .double_bit => |d| @floatFromInt(@intFromEnum(d)),
    };
}

// ── a link+transport+application session ────────────────────────────────────

/// Wraps an `Outstation` in the transport function and the data-link layer, so
/// a caller can feed it whole link frames and get whole link frames back.
///
/// This is where the layer boundary the module's doc comment describes is
/// actually crossed: the outstation itself never sees a link frame, and this
/// type never sees an object header.
pub const Session = struct {
    outstation: *Outstation,
    /// Reassembly buffer for inbound fragments.
    rx: transport.Reassembler,
    /// Scratch for one decoded frame's user data.
    scratch: []u8,
    /// Scratch for one outbound application fragment.
    tx_fragment: []u8,
    /// The transport-function sequence number our next outbound fragment
    /// starts at. It advances across fragments, which is what a master's
    /// reassembler expects.
    tx_seq: u6 = 0,

    pub const SessionError = Error || link.EncodeError || link.DecodeError ||
        transport.ReassembleError;

    pub fn init(
        outstation: *Outstation,
        rx_buf: []u8,
        scratch: []u8,
        tx_fragment: []u8,
    ) Session {
        return .{
            .outstation = outstation,
            .rx = transport.Reassembler.init(rx_buf),
            .scratch = scratch,
            .tx_fragment = tx_fragment,
        };
    }

    /// Feeds one complete data-link frame. Returns the concatenated reply
    /// frames written into `out`, or null when there is nothing to send
    /// (the fragment is incomplete, or the application had no reply).
    pub fn feedFrame(self: *Session, frame_bytes: []const u8, now_ms: u64, out: []u8) SessionError!?[]u8 {
        const decoded = try link.decodeFrame(frame_bytes, self.scratch);
        const control = decoded.control;

        // Data-link layer service requests get data-link answers.
        if (control.prm) {
            switch (control.primaryFunction()) {
                .reset_link_states => return try self.linkReply(.ack, decoded.src, out),
                .request_link_status => return try self.linkReply(.link_status, decoded.src, out),
                .test_link_states => return try self.linkReply(.ack, decoded.src, out),
                .confirmed_user_data, .unconfirmed_user_data => {},
                _ => return null,
            }
        } else {
            // A secondary (response) frame from the master: nothing to do.
            return null;
        }

        const fragment = (try self.rx.feed(self.scratch[0..decoded.user_data_len])) orelse return null;
        const reply = (try self.outstation.handle(fragment, now_ms, self.tx_fragment)) orelse {
            // A CONFIRM that lands mid-series releases the next fragment.
            if (self.outstation.cursor != null) return try self.nextFrames(now_ms, out);
            return null;
        };
        return try self.sendFragment(reply.fragment, out);
    }

    /// Emits the next fragment of a multi-fragment response as link frames.
    pub fn nextFrames(self: *Session, now_ms: u64, out: []u8) SessionError!?[]u8 {
        const reply = (try self.outstation.next(now_ms, self.tx_fragment)) orelse return null;
        return try self.sendFragment(reply.fragment, out);
    }

    fn sendFragment(self: *Session, fragment: []const u8, out: []u8) SessionError![]u8 {
        const control = link.Control{
            // §9.2.4.1.2: DIR is 1 for frames sent *by the master*, 0 for
            // frames sent by the outstation. Getting this backwards makes a
            // real master log "master frame received for master" and drop
            // every reply -- which is exactly what opendnp3's master-demo did
            // to the first draft of this code.
            .dir = false,
            .prm = true,
            .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data),
        };
        var seg = transport.Segmenter.init(fragment);
        seg.seq = self.tx_seq;
        var seg_buf: [1 + transport.max_segment_payload]u8 = undefined;
        var pos: usize = 0;
        while (seg.next(&seg_buf)) |segment| {
            const frame = try link.encodeFrame(
                control,
                self.outstation.config.master_address,
                self.outstation.config.address,
                segment,
                out[pos..],
            );
            pos += frame.len;
        }
        self.tx_seq = seg.seq;
        return out[0..pos];
    }

    fn linkReply(self: *Session, function: link.SecondaryFunction, dest: u16, out: []u8) SessionError![]u8 {
        const control = link.Control{
            .dir = false, // outstation -> master, see sendFragment
            .prm = false,
            .fcv_or_dfc = false,
            .function = @intFromEnum(function),
        };
        return try link.encodeFrame(control, dest, self.outstation.config.address, &.{}, out);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A small outstation used by most tests below.
const Fixture = struct {
    binaries: [6]BinaryInput = undefined,
    dbits: [2]DoubleBitInput = undefined,
    bouts: [4]BinaryOutputStatus = undefined,
    counters: [3]Counter = undefined,
    frozen: [3]FrozenCounter = undefined,
    analogs: [4]AnalogInput = undefined,
    aouts: [2]AnalogOutputStatus = undefined,
    event_storage: [8]Event = undefined,

    fn station(self: *Fixture, config: Config) Outstation {
        for (&self.binaries, 0..) |*p, i| p.* = .{ .value = (i % 2 == 0), .class = .class1, .static_variation = 2, .event_variation = 2 };
        for (&self.dbits, 0..) |*p, i| p.* = .{ .value = @enumFromInt(@as(u2, @intCast(i + 1))), .class = .class1 };
        for (&self.bouts) |*p| p.* = .{ .value = false, .class = .class1 };
        for (&self.counters, 0..) |*p, i| p.* = .{ .value = @intCast(100 + i), .class = .class3 };
        for (&self.frozen) |*p| p.* = .{ .value = 0, .class = null };
        for (&self.analogs, 0..) |*p, i| p.* = .{ .value = @floatFromInt(i * 5), .class = .class2 };
        for (&self.aouts) |*p| p.* = .{ .value = 0, .class = null, .min = -100, .max = 100 };
        return Outstation.init(config, .{
            .binary_inputs = &self.binaries,
            .double_bit_inputs = &self.dbits,
            .binary_outputs = &self.bouts,
            .counters = &self.counters,
            .frozen_counters = &self.frozen,
            .analog_inputs = &self.analogs,
            .analog_outputs = &self.aouts,
        }, EventBuffer.init(&self.event_storage));
    }
};

fn buildRead(buf: []u8, seq: u4, headers: []const objects.ObjectHeader) ![]u8 {
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = seq }, .function = .read },
        buf,
    )).len;
    for (headers) |h| pos += (try objects.encodeObjectHeader(h, buf[pos..])).len;
    return buf[0..pos];
}

fn responseIin(fragment: []const u8) !Iin {
    const decoded = try application.decodeResponseHeader(fragment);
    return decoded.header.iin;
}

/// Walks a response fragment's object headers, calling `visit` for each.
fn objectHeaders(fragment: []const u8, out: []objects.ObjectHeader) !usize {
    const decoded = try application.decodeResponseHeader(fragment);
    var rest = decoded.rest;
    var n: usize = 0;
    while (rest.len > 0 and n < out.len) {
        const hdr = objects.decodeObjectHeader(rest) catch break;
        out[n] = hdr.header;
        n += 1;
        rest = rest[hdr.consumed..];
        // Skip the data belonging to this header.
        const layout = records.layoutOf(hdr.header.group, hdr.header.variation) orelse break;
        const count: usize = switch (hdr.header.range) {
            .start_stop => |r| r.stop - r.start + 1,
            .count => |c| c,
            .all_values => break,
        };
        const prefix: usize = switch (hdr.header.qualifier.prefix_code) {
            .none => 0,
            .index_1b => 1,
            .index_2b => 2,
            else => break,
        };
        const size = if (layout.isPacked())
            (if (layout.value == .packed_bit) records.packedBitBytes(count) else records.packedDoubleBitBytes(count))
        else
            count * (layout.wireLen().? + prefix);
        if (size > rest.len) break;
        rest = rest[size..];
    }
    return n;
}

// ── IIN ─────────────────────────────────────────────────────────────────────

test "IIN: restart is set at start-up and only an explicit WRITE clears it" {
    var fix = Fixture{};
    var station = fix.station(.{ .need_time_at_start = true });
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;

    const read = try buildRead(&req, 0, &.{objects.g60.readClassHeader(.class1)});
    var reply = (try station.handle(read, 100, &out)).?;
    var bits = try responseIin(reply.fragment);
    try testing.expect(bits.device_restart);
    try testing.expect(bits.need_time);

    // WRITE g80v1 [7,7] with the bit clear.
    const write = [_]u8{ 0xC1, 0x02, 80, 1, 0x00, 7, 7, 0x00 };
    reply = (try station.handle(&write, 200, &out)).?;
    bits = try responseIin(reply.fragment);
    try testing.expect(!bits.device_restart);

    // A WRITE of time-and-date clears NEED_TIME.
    var time_req: [16]u8 = undefined;
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 2 }, .function = .write },
        &time_req,
    )).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 50,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
        .range = .{ .count = 1 },
    }, time_req[pos..])).len;
    pos += (try (objects.g50.V1{ .ms_since_epoch = 1_700_000_000_000 }).encode(time_req[pos..])).len;
    reply = (try station.handle(time_req[0..pos], 300, &out)).?;
    bits = try responseIin(reply.fragment);
    try testing.expect(!bits.need_time);
    try testing.expect(!bits.device_restart);
}

test "IIN: class-event bits track the buffer, and overflow latches until it drains" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;

    try testing.expect(!station.iin().class_1_events);
    station.update(.binary_input, 0, .{ .binary = true }, 10);
    try testing.expect(station.iin().class_1_events);
    try testing.expect(!station.iin().class_2_events);
    station.update(.analog_input, 0, .{ .analog_int = 7 }, 20);
    try testing.expect(station.iin().class_2_events);
    station.update(.counter, 0, .{ .counter = 5 }, 30);
    try testing.expect(station.iin().class_3_events);

    // The buffer holds 8; push 12 and the oldest four are lost.
    for (0..12) |i| station.update(.binary_input, 1, .{ .binary = i % 2 == 0 }, 40 + i);
    try testing.expect(station.iin().event_buffer_overflow);
    try testing.expectEqual(@as(usize, 8), station.events.len);

    // Draining clears the latch.
    var req: [64]u8 = undefined;
    const read = try buildRead(&req, 0, &.{objects.g60.readClassHeader(.class1)});
    const reply = (try station.handle(read, 200, &out)).?;
    try testing.expect(reply.confirm_requested);
    const confirm = [_]u8{ 0xC0, 0x00 };
    try testing.expectEqual(@as(?Reply, null), try station.handle(&confirm, 210, &out));
    try testing.expect(station.events.isEmpty());
    try testing.expect(!station.iin().event_buffer_overflow);
}

test "IIN: an unimplemented function code answers FUNC_NOT_SUPPORTED" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    for ([_]u8{ 0x19, 0x1A, 0x1B, 0x1C, 0x1F, 0x77, 0xFE }) |func| {
        const req = [_]u8{ 0xC0, func };
        const reply = (try station.handle(&req, 100, &out)).?;
        const bits = try responseIin(reply.fragment);
        try testing.expect(bits.func_not_supported);
    }
}

test "IIN: an unknown object group answers OBJECT_UNKNOWN" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;
    const read = try buildRead(&req, 0, &.{.{
        .group = 87, // data sets: not implemented
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    const reply = (try station.handle(read, 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).object_unknown);
}

// ── READ ────────────────────────────────────────────────────────────────────

test "READ class 0 walks every point type once, in order" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [1024]u8 = undefined;
    var req: [64]u8 = undefined;

    const read = try buildRead(&req, 3, &.{objects.g60.readClassHeader(.class0)});
    const reply = (try station.handle(read, 100, &out)).?;
    try testing.expect(!reply.more);

    var headers: [16]objects.ObjectHeader = undefined;
    const n = try objectHeaders(reply.fragment, &headers);
    try testing.expectEqual(@as(usize, 7), n);
    const want_groups = [_]u8{ 1, 3, 10, 20, 21, 30, 40 };
    for (want_groups, 0..) |g, i| try testing.expectEqual(g, headers[i].group);
    // Every one covers its whole range.
    try testing.expectEqual(@as(u32, 0), headers[0].range.start_stop.start);
    try testing.expectEqual(@as(u32, 5), headers[0].range.start_stop.stop);
    try testing.expectEqual(@as(u32, 1), headers[1].range.start_stop.stop); // 2 double-bit points
    try testing.expectEqual(@as(u32, 1), headers[6].range.start_stop.stop); // 2 analog outputs

    // The application sequence number is echoed.
    const decoded = try application.decodeResponseHeader(reply.fragment);
    try testing.expectEqual(@as(u4, 3), decoded.header.control.seq);
    try testing.expect(decoded.header.control.fir and decoded.header.control.fin);
}

test "READ specific group/variation with every qualifier shape" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [1024]u8 = undefined;
    var req: [64]u8 = undefined;
    var headers: [4]objects.ObjectHeader = undefined;

    // 8-bit start-stop.
    var read = try buildRead(&req, 0, &.{.{
        .group = 1,
        .variation = 2,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 1, .stop = 3 } },
    }});
    var reply = (try station.handle(read, 10, &out)).?;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
    try testing.expectEqual(@as(u32, 1), headers[0].range.start_stop.start);
    try testing.expectEqual(@as(u32, 3), headers[0].range.start_stop.stop);
    // The points must be 1,2,3 -> false,true,false (even indices are on).
    const body = (try application.decodeResponseHeader(reply.fragment)).rest[5..];
    try testing.expectEqual(@as(u8, 0x01), body[0]); // point 1: off, online
    try testing.expectEqual(@as(u8, 0x81), body[1]); // point 2: on, online

    // 16-bit start-stop.
    read = try buildRead(&req, 1, &.{.{
        .group = 30,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_2b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 3 } },
    }});
    reply = (try station.handle(read, 20, &out)).?;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
    try testing.expectEqual(@as(u8, 30), headers[0].group);

    // All-objects.
    read = try buildRead(&req, 2, &.{.{
        .group = 20,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    reply = (try station.handle(read, 30, &out)).?;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
    try testing.expectEqual(@as(u32, 2), headers[0].range.start_stop.stop);

    // Count.
    read = try buildRead(&req, 3, &.{.{
        .group = 20,
        .variation = 2,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
        .range = .{ .count = 2 },
    }});
    reply = (try station.handle(read, 40, &out)).?;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
    try testing.expectEqual(@as(u8, 2), headers[0].variation);
    try testing.expectEqual(@as(u32, 1), headers[0].range.start_stop.stop);

    // Variation 0 ("any"): each point's declared static variation is used.
    read = try buildRead(&req, 4, &.{.{
        .group = 1,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    reply = (try station.handle(read, 50, &out)).?;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
    try testing.expectEqual(@as(u8, 2), headers[0].variation); // the fixture declares v2
}

test "READ: packed variations pack, and a mixed-variation run splits headers" {
    var binaries = [_]BinaryInput{
        .{ .value = true, .static_variation = 1 },
        .{ .value = false, .static_variation = 1 },
        .{ .value = true, .static_variation = 1 },
        .{ .value = true, .static_variation = 2 }, // a different shape
    };
    var storage: [4]Event = undefined;
    var station = Outstation.init(.{}, .{ .binary_inputs = &binaries }, EventBuffer.init(&storage));
    var out: [256]u8 = undefined;
    var req: [32]u8 = undefined;
    var headers: [4]objects.ObjectHeader = undefined;

    const read = try buildRead(&req, 0, &.{.{
        .group = 1,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    const reply = (try station.handle(read, 10, &out)).?;
    const n = try objectHeaders(reply.fragment, &headers);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u8, 1), headers[0].variation);
    try testing.expectEqual(@as(u32, 2), headers[0].range.start_stop.stop);
    try testing.expectEqual(@as(u8, 2), headers[1].variation);
    try testing.expectEqual(@as(u32, 3), headers[1].range.start_stop.start);

    // The packed byte is 0b101 = 0x05.
    const body = (try application.decodeResponseHeader(reply.fragment)).rest;
    try testing.expectEqual(@as(u8, 0x05), body[5]);
}

test "READ: hostile ranges are PARAMETER_ERROR, never an out-of-bounds read" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;

    // Inverted range (stop < start).
    var read = try buildRead(&req, 0, &.{.{
        .group = 1,
        .variation = 2,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 4, .stop = 1 } },
    }});
    var reply = (try station.handle(read, 10, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);

    // Range past the end of the database.
    read = try buildRead(&req, 1, &.{.{
        .group = 1,
        .variation = 2,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_2b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 60000 } },
    }});
    reply = (try station.handle(read, 20, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);

    // Count larger than the database.
    read = try buildRead(&req, 2, &.{.{
        .group = 30,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_2b },
        .range = .{ .count = 5000 },
    }});
    reply = (try station.handle(read, 30, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);

    // A variation we do not implement.
    read = try buildRead(&req, 3, &.{.{
        .group = 30,
        .variation = 9,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    reply = (try station.handle(read, 40, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).object_unknown);

    // An object header that runs off the end of the fragment.
    const truncated = [_]u8{ 0xC0, 0x01, 1, 2, 0x00, 3 }; // start-stop needs two range octets
    reply = (try station.handle(&truncated, 50, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);
}

// ── events ──────────────────────────────────────────────────────────────────

test "events: reported oldest-first with the right group, retired only on CONFIRM" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;

    station.update(.binary_input, 2, .{ .binary = false }, 1000);
    station.update(.binary_input, 4, .{ .binary = false }, 2000);
    try testing.expectEqual(@as(usize, 2), station.events.countOf(.class1));

    const read = try buildRead(&req, 5, &.{objects.g60.readClassHeader(.class1)});
    const reply = (try station.handle(read, 3000, &out)).?;
    try testing.expect(reply.confirm_requested);
    try testing.expect(!reply.more);

    var headers: [4]objects.ObjectHeader = undefined;
    const n = try objectHeaders(reply.fragment, &headers);
    try testing.expectEqual(@as(usize, 2), n);
    for (headers[0..2]) |h| {
        try testing.expectEqual(@as(u8, 2), h.group); // g2 binary input event
        try testing.expectEqual(@as(u8, 2), h.variation); // with absolute time
        try testing.expectEqual(objects.PrefixCode.index_1b, h.qualifier.prefix_code);
        try testing.expectEqual(objects.RangeCode.count_1b, h.qualifier.range_code);
    }
    // Index prefixes are the point indices, oldest first.
    const body = (try application.decodeResponseHeader(reply.fragment)).rest;
    try testing.expectEqual(@as(u8, 2), body[4]);
    try testing.expectEqual(@as(u8, 4), body[4 + 1 + 7 + 4]);

    // Still buffered until the master confirms.
    try testing.expectEqual(@as(usize, 2), station.events.len);
    try testing.expectEqual(@as(usize, 2), station.events.in_flight);

    const confirm = [_]u8{ 0xC5, 0x00 };
    try testing.expectEqual(@as(?Reply, null), try station.handle(&confirm, 3100, &out));
    try testing.expect(station.events.isEmpty());
}

test "events: a confirm that never arrives puts them back on the queue" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;

    station.update(.binary_input, 0, .{ .binary = false }, 1000);
    const read = try buildRead(&req, 0, &.{objects.g60.readClassHeader(.class1)});
    _ = (try station.handle(read, 2000, &out)).?;
    try testing.expectEqual(@as(usize, 1), station.events.in_flight);

    station.confirmTimedOut();
    try testing.expectEqual(@as(usize, 0), station.events.in_flight);
    try testing.expectEqual(@as(usize, 1), station.events.len);

    // The next poll offers the same event again.
    const read2 = try buildRead(&req, 1, &.{objects.g60.readClassHeader(.class1)});
    const reply = (try station.handle(read2, 3000, &out)).?;
    var headers: [2]objects.ObjectHeader = undefined;
    try testing.expectEqual(@as(usize, 1), try objectHeaders(reply.fragment, &headers));
}

test "events: only the requested class is reported" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;

    station.update(.binary_input, 0, .{ .binary = false }, 10); // class 1
    station.update(.analog_input, 0, .{ .analog_int = 1 }, 20); // class 2
    station.update(.counter, 0, .{ .counter = 1 }, 30); // class 3

    var headers: [4]objects.ObjectHeader = undefined;
    const classes = [_]objects.g60.Class{ .class1, .class2, .class3 };
    const want_groups = [_]u8{ 2, 32, 22 };
    for (classes, want_groups, 0..) |class, group, i| {
        const read = try buildRead(&req, @intCast(i), &.{objects.g60.readClassHeader(class)});
        const reply = (try station.handle(read, 100 + i * 10, &out)).?;
        const n = try objectHeaders(reply.fragment, &headers);
        try testing.expectEqual(@as(usize, 1), n);
        try testing.expectEqual(group, headers[0].group);
        // Confirm, so the next class poll starts clean.
        const confirm = [_]u8{ 0xC0 | @as(u8, @intCast(i)), 0x00 };
        _ = try station.handle(&confirm, 105 + i * 10, &out);
    }
}

test "events: a direct read of an event group works, with and without a count limit" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [512]u8 = undefined;
    var req: [64]u8 = undefined;
    var headers: [8]objects.ObjectHeader = undefined;

    for (0..3) |i| station.update(.binary_input, @intCast(i), .{ .binary = false }, 10 + i);

    // g2v0, count 2: only the two oldest.
    const read = try buildRead(&req, 0, &.{.{
        .group = 2,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
        .range = .{ .count = 2 },
    }});
    const reply = (try station.handle(read, 100, &out)).?;
    try testing.expectEqual(@as(usize, 2), try objectHeaders(reply.fragment, &headers));

    // g2v0, all objects: everything.
    station.confirmTimedOut();
    const read_all = try buildRead(&req, 1, &.{.{
        .group = 2,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }});
    const reply2 = (try station.handle(read_all, 200, &out)).?;
    try testing.expectEqual(@as(usize, 3), try objectHeaders(reply2.fragment, &headers));
}

test "event buffer: overflow drops the oldest and latches, confirm retires the prefix" {
    var storage: [3]Event = undefined;
    var buffer = EventBuffer.init(&storage);
    const template = Event{
        .kind = .binary_input,
        .index = 0,
        .class = .class1,
        .variation = 2,
        .flags = .{},
        .value = .{ .binary = true },
        .time_ms = 0,
    };
    for (0..3) |i| {
        var ev = template;
        ev.index = @intCast(i);
        buffer.push(ev);
    }
    try testing.expectEqual(@as(usize, 3), buffer.len);
    try testing.expect(!buffer.overflowed);

    var ev = template;
    ev.index = 99;
    buffer.push(ev);
    try testing.expect(buffer.overflowed);
    try testing.expectEqual(@as(usize, 3), buffer.len);
    try testing.expectEqual(@as(u16, 1), buffer.at(0).index); // index 0 was dropped
    try testing.expectEqual(@as(u16, 99), buffer.at(2).index);

    buffer.in_flight = 2;
    buffer.confirm();
    try testing.expectEqual(@as(usize, 1), buffer.len);
    try testing.expectEqual(@as(u16, 99), buffer.at(0).index);
    try testing.expect(buffer.overflowed); // still latched: not empty yet
    buffer.in_flight = 1;
    buffer.confirm();
    try testing.expect(!buffer.overflowed);

    // A zero-capacity buffer never crashes; it just overflows.
    var none = EventBuffer.init(&.{});
    none.push(template);
    try testing.expect(none.overflowed);
    try testing.expect(none.isEmpty());
}

// ── SELECT / OPERATE ────────────────────────────────────────────────────────

/// Builds a CROB command fragment with a 1-byte index prefix.
fn buildCrob(buf: []u8, seq: u4, function: FunctionCode, index: u8, op: objects.g12.OpType) ![]u8 {
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = seq }, .function = function },
        buf,
    )).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 12,
        .variation = 1,
        .qualifier = .{ .prefix_code = .index_1b, .range_code = .count_1b },
        .range = .{ .count = 1 },
    }, buf[pos..])).len;
    buf[pos] = index;
    pos += 1;
    pos += (try (objects.g12.V1{
        .control_code = .{ .op_type = op },
        .count = 1,
        .on_time_ms = 100,
        .off_time_ms = 100,
    }).encode(buf[pos..])).len;
    return buf[0..pos];
}

/// The status byte of the first echoed command object in a response.
fn commandStatus(fragment: []const u8) !CommandStatus {
    const decoded = try application.decodeResponseHeader(fragment);
    return @enumFromInt(decoded.rest[decoded.rest.len - 1]);
}

test "SELECT then OPERATE executes exactly once, and arms nothing afterwards" {
    var fix = Fixture{};
    var station = fix.station(.{ .select_timeout_ms = 5000 });
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const select = try buildCrob(&req, 1, .select, 2, .latch_on);
    var reply = (try station.handle(select, 1000, &out)).?;
    try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[2].value); // a SELECT changes nothing

    var req2: [64]u8 = undefined;
    const operate = try buildCrob(&req2, 2, .operate, 2, .latch_on);
    reply = (try station.handle(operate, 2000, &out)).?;
    try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
    try testing.expect(fix.bouts[2].value);
    try testing.expectEqual(@as(?Outstation.Select, null), station.select);

    // A second OPERATE without a fresh SELECT is refused.
    var req3: [64]u8 = undefined;
    const again = try buildCrob(&req3, 3, .operate, 2, .latch_off);
    reply = (try station.handle(again, 3000, &out)).?;
    try testing.expectEqual(CommandStatus.no_select, try commandStatus(reply.fragment));
    try testing.expect(fix.bouts[2].value); // unchanged
}

test "OPERATE after the select timer expires is TIMEOUT, and does not execute" {
    var fix = Fixture{};
    var station = fix.station(.{ .select_timeout_ms = 1000 });
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const select = try buildCrob(&req, 1, .select, 0, .latch_on);
    _ = (try station.handle(select, 1000, &out)).?;
    try testing.expectEqual(@as(?u64, 2000), station.nextDeadline());

    var req2: [64]u8 = undefined;
    const operate = try buildCrob(&req2, 2, .operate, 0, .latch_on);
    // 1000 ms later exactly: the window has closed.
    const reply = (try station.handle(operate, 2000, &out)).?;
    try testing.expectEqual(CommandStatus.timeout, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[0].value);
}

test "OPERATE with the wrong sequence or different objects is NO_SELECT" {
    var fix = Fixture{};
    var station = fix.station(.{ .select_timeout_ms = 10_000 });
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;
    var req2: [64]u8 = undefined;

    // Wrong sequence number: the OPERATE must be SELECT's seq + 1.
    const select = try buildCrob(&req, 1, .select, 0, .latch_on);
    _ = (try station.handle(select, 1000, &out)).?;
    const bad_seq = try buildCrob(&req2, 5, .operate, 0, .latch_on);
    var reply = (try station.handle(bad_seq, 1100, &out)).?;
    try testing.expectEqual(CommandStatus.no_select, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[0].value);

    // Different objects: same point, different operation.
    const select2 = try buildCrob(&req, 6, .select, 0, .latch_on);
    _ = (try station.handle(select2, 2000, &out)).?;
    const different = try buildCrob(&req2, 7, .operate, 0, .latch_off);
    reply = (try station.handle(different, 2100, &out)).?;
    try testing.expectEqual(CommandStatus.no_select, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[0].value);

    // Different index.
    const select3 = try buildCrob(&req, 8, .select, 0, .latch_on);
    _ = (try station.handle(select3, 3000, &out)).?;
    const other_index = try buildCrob(&req2, 9, .operate, 1, .latch_on);
    reply = (try station.handle(other_index, 3100, &out)).?;
    try testing.expectEqual(CommandStatus.no_select, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[1].value);
}

test "DIRECT_OPERATE executes without a select; the no-ack form sends nothing" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const direct = try buildCrob(&req, 1, .direct_operate, 1, .latch_on);
    const reply = (try station.handle(direct, 100, &out)).?;
    try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
    try testing.expect(fix.bouts[1].value);

    const no_ack = try buildCrob(&req, 2, .direct_operate_no_ack, 3, .latch_on);
    try testing.expectEqual(@as(?Reply, null), try station.handle(no_ack, 200, &out));
    try testing.expect(fix.bouts[3].value); // executed anyway
}

test "CROB operations map to the right output state and raise an event" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const cases = [_]struct { op: objects.g12.OpType, want: bool }{
        .{ .op = .latch_on, .want = true },
        .{ .op = .latch_off, .want = false },
        .{ .op = .pulse_on, .want = true },
        .{ .op = .pulse_off, .want = false },
    };
    for (cases, 0..) |c, i| {
        const direct = try buildCrob(&req, @intCast(i), .direct_operate, 0, c.op);
        const reply = (try station.handle(direct, 100 + i * 10, &out)).?;
        try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
        try testing.expectEqual(c.want, fix.bouts[0].value);
    }
    // Each one raised a binary-output-status event (the fixture puts them in
    // class 1).
    try testing.expect(station.events.countOf(.class1) >= 4);

    // A NUL operation is accepted but changes nothing.
    fix.bouts[0].value = true;
    const nul = try buildCrob(&req, 8, .direct_operate, 0, .nul);
    const reply = (try station.handle(nul, 500, &out)).?;
    try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
    try testing.expect(fix.bouts[0].value);
}

test "commands against a nonexistent or command-less point are NOT_SUPPORTED" {
    var fix = Fixture{};
    var station = fix.station(.{});
    fix.bouts[1].supports_commands = false;
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const missing = try buildCrob(&req, 0, .direct_operate, 200, .latch_on);
    var reply = (try station.handle(missing, 100, &out)).?;
    try testing.expectEqual(CommandStatus.not_supported, try commandStatus(reply.fragment));

    const blocked = try buildCrob(&req, 1, .direct_operate, 1, .latch_on);
    reply = (try station.handle(blocked, 200, &out)).?;
    try testing.expectEqual(CommandStatus.not_supported, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[1].value);
}

test "analog output block: value written, bounds enforced" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    const write = struct {
        fn build(buf: []u8, seq: u4, index: u8, value: i32) ![]u8 {
            var pos = (try application.encodeRequestHeader(
                .{ .control = .{ .fir = true, .fin = true, .seq = seq }, .function = .direct_operate },
                buf,
            )).len;
            pos += (try objects.encodeObjectHeader(.{
                .group = 41,
                .variation = 1,
                .qualifier = .{ .prefix_code = .index_1b, .range_code = .count_1b },
                .range = .{ .count = 1 },
            }, buf[pos..])).len;
            buf[pos] = index;
            pos += 1;
            pos += (try (objects.g41.V1{ .value = value }).encode(buf[pos..])).len;
            return buf[0..pos];
        }
    };

    const ok = try write.build(&req, 0, 0, 42);
    var reply = (try station.handle(ok, 100, &out)).?;
    try testing.expectEqual(CommandStatus.success, try commandStatus(reply.fragment));
    try testing.expectEqual(@as(f64, 42), fix.aouts[0].value);

    const too_big = try write.build(&req, 1, 0, 5000); // the fixture caps at 100
    reply = (try station.handle(too_big, 200, &out)).?;
    try testing.expectEqual(CommandStatus.out_of_range, try commandStatus(reply.fragment));
    try testing.expectEqual(@as(f64, 42), fix.aouts[0].value); // unchanged
}

test "the command hook can veto, and sees select and operate separately" {
    const Recorder = struct {
        kinds: [4]CommandKind = undefined,
        n: usize = 0,
        verdict: CommandStatus = .success,

        fn hook(self: *@This()) CommandHook {
            return .{ .ctx = self, .onCommandFn = onCommand };
        }

        fn onCommand(ctx: *anyopaque, kind: CommandKind, command: Command) CommandStatus {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = command;
            if (self.n < self.kinds.len) self.kinds[self.n] = kind;
            self.n += 1;
            return self.verdict;
        }
    };

    var fix = Fixture{};
    var station = fix.station(.{ .select_timeout_ms = 10_000 });
    var rec = Recorder{};
    station.setCommandHook(rec.hook());
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;
    var req2: [64]u8 = undefined;

    _ = (try station.handle(try buildCrob(&req, 1, .select, 0, .latch_on), 100, &out)).?;
    _ = (try station.handle(try buildCrob(&req2, 2, .operate, 0, .latch_on), 200, &out)).?;
    try testing.expectEqual(@as(usize, 2), rec.n);
    try testing.expectEqual(CommandKind.select, rec.kinds[0]);
    try testing.expectEqual(CommandKind.operate, rec.kinds[1]);
    try testing.expect(fix.bouts[0].value);

    // A veto stops the write.
    fix.bouts[0].value = false;
    rec.verdict = .blocked;
    const reply = (try station.handle(try buildCrob(&req, 3, .direct_operate, 0, .latch_on), 300, &out)).?;
    try testing.expectEqual(CommandStatus.blocked, try commandStatus(reply.fragment));
    try testing.expect(!fix.bouts[0].value);
}

// ── other function codes ────────────────────────────────────────────────────

test "DELAY_MEASURE answers g52v2 with the configured delay" {
    var fix = Fixture{};
    var station = fix.station(.{ .delay_measure_ms = 1234 });
    var out: [64]u8 = undefined;
    const req = [_]u8{ 0xC0, 0x17 };
    const reply = (try station.handle(&req, 100, &out)).?;
    const decoded = try application.decodeResponseHeader(reply.fragment);
    const hdr = try objects.decodeObjectHeader(decoded.rest);
    try testing.expectEqual(@as(u8, 52), hdr.header.group);
    try testing.expectEqual(@as(u8, 2), hdr.header.variation);
    try testing.expectEqual(@as(u16, 1234), std.mem.readInt(u16, decoded.rest[hdr.consumed..][0..2], .little));
}

test "restart is refused unless configured, and resets everything when allowed" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [128]u8 = undefined;

    const cold = [_]u8{ 0xC0, 0x0D };
    var reply = (try station.handle(&cold, 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).func_not_supported);

    var fix2 = Fixture{};
    var allowed = fix2.station(.{ .allow_restart = true, .restart_delay_ms = 250 });
    allowed.restart = false;
    allowed.update(.binary_input, 0, .{ .binary = false }, 10);
    try testing.expect(!allowed.events.isEmpty());

    reply = (try allowed.handle(&cold, 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).device_restart);
    try testing.expect(allowed.events.isEmpty());
    const decoded = try application.decodeResponseHeader(reply.fragment);
    const hdr = try objects.decodeObjectHeader(decoded.rest);
    try testing.expectEqual(@as(u8, 52), hdr.header.group);
    try testing.expectEqual(@as(u16, 250), std.mem.readInt(u16, decoded.rest[hdr.consumed..][0..2], .little));

    // WARM_RESTART takes the same path.
    const warm = [_]u8{ 0xC1, 0x0E };
    reply = (try allowed.handle(&warm, 200, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).device_restart);
}

test "ENABLE/DISABLE_UNSOLICITED toggles the classes, or is refused outright" {
    var fix = Fixture{};
    var unsupported = fix.station(.{});
    var out: [128]u8 = undefined;
    var req: [64]u8 = undefined;

    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 0 }, .function = .enable_unsolicited },
        &req,
    )).len;
    for ([_]objects.g60.Class{ .class1, .class2, .class3 }) |c| {
        pos += (try objects.encodeObjectHeader(objects.g60.readClassHeader(c), req[pos..])).len;
    }
    var reply = (try unsupported.handle(req[0..pos], 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).func_not_supported);

    var fix2 = Fixture{};
    var supported = fix2.station(.{ .unsolicited_supported = true });
    try testing.expectEqualSlices(bool, &.{ false, false, false }, &supported.unsolicited_enabled);
    reply = (try supported.handle(req[0..pos], 100, &out)).?;
    try testing.expect(!(try responseIin(reply.fragment)).func_not_supported);
    try testing.expectEqualSlices(bool, &.{ true, true, true }, &supported.unsolicited_enabled);

    req[0] = 0xC1;
    req[1] = @intFromEnum(FunctionCode.disable_unsolicited);
    _ = (try supported.handle(req[0..pos], 200, &out)).?;
    try testing.expectEqualSlices(bool, &.{ false, false, false }, &supported.unsolicited_enabled);
}

test "unsolicited responses carry UNS, ask for a confirm, and stop while one is pending" {
    var fix = Fixture{};
    var station = fix.station(.{
        .unsolicited_supported = true,
        .unsolicited_enabled_at_start = true,
    });
    station.restart = false;
    var out: [512]u8 = undefined;

    // Nothing buffered -> nothing to send.
    try testing.expectEqual(@as(?Reply, null), try station.unsolicited(100, &out));

    station.update(.binary_input, 3, .{ .binary = false }, 200);
    const reply = (try station.unsolicited(300, &out)).?;
    try testing.expect(reply.unsolicited);
    try testing.expect(reply.confirm_requested);
    const decoded = try application.decodeResponseHeader(reply.fragment);
    try testing.expectEqual(FunctionCode.unsolicited_response, decoded.header.function);
    try testing.expect(decoded.header.control.uns);
    try testing.expect(decoded.header.control.con);

    // A second one is not built until the first is confirmed.
    station.update(.binary_input, 4, .{ .binary = false }, 400);
    try testing.expectEqual(@as(?Reply, null), try station.unsolicited(500, &out));

    const confirm = [_]u8{ 0xD0, 0x00 }; // UNS set
    try testing.expectEqual(@as(?Reply, null), try station.handle(&confirm, 600, &out));
    try testing.expect((try station.unsolicited(700, &out)) != null);

    // An outstation that is still in its restart state stays quiet.
    var fix2 = Fixture{};
    var restarted = fix2.station(.{
        .unsolicited_supported = true,
        .unsolicited_enabled_at_start = true,
    });
    restarted.update(.binary_input, 0, .{ .binary = false }, 100);
    try testing.expectEqual(@as(?Reply, null), try restarted.unsolicited(200, &out));
}

test "IMMEDIATE_FREEZE copies counters into frozen counters, freeze-clear zeroes them" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    // No object headers = freeze everything.
    const all = [_]u8{ 0xC0, 0x07 };
    _ = (try station.handle(&all, 100, &out)).?;
    try testing.expectEqual(@as(u32, 100), fix.frozen[0].value);
    try testing.expectEqual(@as(u32, 102), fix.frozen[2].value);
    try testing.expectEqual(@as(u32, 100), fix.counters[0].value); // not cleared

    fix.counters[0].value = 555;
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 1 }, .function = .freeze_clear },
        &req,
    )).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 20,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 0 } },
    }, req[pos..])).len;
    _ = (try station.handle(req[0..pos], 200, &out)).?;
    try testing.expectEqual(@as(u32, 555), fix.frozen[0].value);
    try testing.expectEqual(@as(u32, 0), fix.counters[0].value);
    try testing.expectEqual(@as(u32, 102), fix.counters[2].value); // untouched

    // The no-ack form answers nothing.
    const no_ack = [_]u8{ 0xC2, 0x08 };
    try testing.expectEqual(@as(?Reply, null), try station.handle(&no_ack, 300, &out));
}

test "ASSIGN_CLASS moves points between classes (and out of them)" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;
    var req: [64]u8 = undefined;

    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 0 }, .function = .assign_class },
        &req,
    )).len;
    pos += (try objects.encodeObjectHeader(objects.g60.readClassHeader(.class3), req[pos..])).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 1,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 2 } },
    }, req[pos..])).len;
    _ = (try station.handle(req[0..pos], 100, &out)).?;
    try testing.expectEqual(EventClass.class3, fix.binaries[0].class.?);
    try testing.expectEqual(EventClass.class3, fix.binaries[2].class.?);
    try testing.expectEqual(EventClass.class1, fix.binaries[3].class.?); // untouched

    // Class 0 means "no events at all".
    req[0] = 0xC1;
    pos = 2;
    pos += (try objects.encodeObjectHeader(objects.g60.readClassHeader(.class0), req[pos..])).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 1,
        .variation = 0,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .all_values = {} },
    }, req[pos..])).len;
    _ = (try station.handle(req[0..pos], 200, &out)).?;
    for (fix.binaries) |p| try testing.expectEqual(@as(?EventClass, null), p.class);
    station.update(.binary_input, 0, .{ .binary = false }, 300);
    try testing.expect(station.events.isEmpty());
}

// ── fragmentation ───────────────────────────────────────────────────────────

test "fragmentation: a big response splits with correct FIR/FIN/SEQ" {
    var binaries: [200]BinaryInput = undefined;
    for (&binaries, 0..) |*p, i| p.* = .{ .value = (i % 2 == 0), .static_variation = 2, .class = null };
    var analogs: [50]AnalogInput = undefined;
    for (&analogs, 0..) |*p, i| p.* = .{ .value = @floatFromInt(i), .static_variation = 1, .class = null };
    var storage: [4]Event = undefined;
    var station = Outstation.init(
        .{ .max_tx_fragment = 100 },
        .{ .binary_inputs = &binaries, .analog_inputs = &analogs },
        EventBuffer.init(&storage),
    );

    var out: [512]u8 = undefined;
    var req: [32]u8 = undefined;
    const read = try buildRead(&req, 7, &.{objects.g60.readClassHeader(.class0)});

    var reply = (try station.handle(read, 100, &out)).?;
    var fragments: usize = 1;
    var total_points: usize = 0;

    var decoded = try application.decodeResponseHeader(reply.fragment);
    try testing.expect(decoded.header.control.fir);
    try testing.expect(!decoded.header.control.fin);
    try testing.expect(decoded.header.control.con);
    try testing.expectEqual(@as(u4, 7), decoded.header.control.seq);
    try testing.expect(reply.fragment.len <= 100);
    total_points += try countPoints(reply.fragment);

    var expected_seq: u4 = 8;
    while (reply.more) {
        // The master confirms, then we produce the next fragment.
        var confirm_buf: [4]u8 = undefined;
        const confirm = try application.encodeRequestHeader(.{
            .control = .{ .fir = true, .fin = true, .seq = decoded.header.control.seq },
            .function = .confirm,
        }, &confirm_buf);
        try testing.expectEqual(@as(?Reply, null), try station.handle(confirm, 200, &out));

        reply = (try station.next(200, &out)).?;
        fragments += 1;
        decoded = try application.decodeResponseHeader(reply.fragment);
        try testing.expect(!decoded.header.control.fir); // FIR only on the first
        try testing.expectEqual(expected_seq, decoded.header.control.seq);
        expected_seq +%= 1;
        try testing.expect(reply.fragment.len <= 100);
        total_points += try countPoints(reply.fragment);
        if (fragments > 40) return error.TestUnexpectedResult;
    }
    try testing.expect(decoded.header.control.fin);
    try testing.expect(fragments > 3);
    try testing.expectEqual(@as(usize, 250), total_points);
    try testing.expectEqual(@as(?Reply, null), try station.next(300, &out));
}

fn countPoints(fragment: []const u8) !usize {
    var headers: [16]objects.ObjectHeader = undefined;
    const n = try objectHeaders(fragment, &headers);
    var total: usize = 0;
    for (headers[0..n]) |h| {
        total += switch (h.range) {
            .start_stop => |r| r.stop - r.start + 1,
            .count => |c| c,
            .all_values => 0,
        };
    }
    return total;
}

test "fragmentation: a new request abandons an unfinished series" {
    var binaries: [200]BinaryInput = undefined;
    for (&binaries) |*p| p.* = .{ .static_variation = 2, .class = null };
    var storage: [2]Event = undefined;
    var station = Outstation.init(
        .{ .max_tx_fragment = 60 },
        .{ .binary_inputs = &binaries },
        EventBuffer.init(&storage),
    );
    var out: [256]u8 = undefined;
    var req: [32]u8 = undefined;

    const read = try buildRead(&req, 0, &.{objects.g60.readClassHeader(.class0)});
    const reply = (try station.handle(read, 100, &out)).?;
    try testing.expect(reply.more);
    try testing.expect(station.cursor != null);

    const other = [_]u8{ 0xC1, 0x17 }; // DELAY_MEASURE
    _ = (try station.handle(&other, 200, &out)).?;
    try testing.expectEqual(@as(?Outstation.Cursor, null), station.cursor);
    try testing.expectEqual(@as(?Reply, null), try station.next(300, &out));
}

// ── link + transport session ────────────────────────────────────────────────

test "Session: link-layer service requests get link-layer answers" {
    var fix = Fixture{};
    var station = fix.station(.{ .address = 10, .master_address = 1 });
    var rx: [512]u8 = undefined;
    var scratch: [256]u8 = undefined;
    var tx: [512]u8 = undefined;
    var session = Session.init(&station, &rx, &scratch, &tx);
    var out: [512]u8 = undefined;
    var frame_buf: [64]u8 = undefined;

    const reset = try link.encodeFrame(
        .{ .dir = true, .prm = true, .fcv_or_dfc = true, .function = @intFromEnum(link.PrimaryFunction.reset_link_states) },
        10,
        1,
        &.{},
        &frame_buf,
    );
    const ack = (try session.feedFrame(reset, 100, &out)).?;
    const decoded = try link.decodeFrame(ack, &scratch);
    try testing.expect(!decoded.control.prm);
    try testing.expect(!decoded.control.dir); // outstation -> master
    try testing.expectEqual(link.SecondaryFunction.ack, decoded.control.secondaryFunction());
    try testing.expectEqual(@as(u16, 1), decoded.dest);
    try testing.expectEqual(@as(u16, 10), decoded.src);

    const status = try link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(link.PrimaryFunction.request_link_status) },
        10,
        1,
        &.{},
        &frame_buf,
    );
    const reply = (try session.feedFrame(status, 200, &out)).?;
    const d2 = try link.decodeFrame(reply, &scratch);
    try testing.expectEqual(link.SecondaryFunction.link_status, d2.control.secondaryFunction());
}

test "Session: a fragment split across transport segments reassembles" {
    var binaries: [200]BinaryInput = undefined;
    for (&binaries) |*p| p.* = .{ .static_variation = 2, .class = null };
    var storage: [2]Event = undefined;
    var station = Outstation.init(
        .{ .address = 10, .master_address = 1 },
        .{ .binary_inputs = &binaries },
        EventBuffer.init(&storage),
    );
    var rx: [1024]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx: [1024]u8 = undefined;
    var session = Session.init(&station, &rx, &scratch, &tx);

    // A read request padded out past one transport segment, so the request
    // itself arrives in two link frames.
    var fragment: [400]u8 = undefined;
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 0 }, .function = .read },
        &fragment,
    )).len;
    // 60 identical single-point read headers: valid, and long enough to split.
    for (0..60) |_| {
        pos += (try objects.encodeObjectHeader(.{
            .group = 1,
            .variation = 2,
            .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
            .range = .{ .start_stop = .{ .start = 0, .stop = 0 } },
        }, fragment[pos..])).len;
    }
    try testing.expect(pos > transport.max_segment_payload);

    var wire: [1024]u8 = undefined;
    const frames = try @import("root.zig").sendFragment(
        .{ .dir = true, .prm = true, .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data) },
        10,
        1,
        fragment[0..pos],
        &wire,
    );

    // Walk the concatenated frames; only the last one completes the fragment.
    var out: [1024]u8 = undefined;
    var offset: usize = 0;
    var replies: usize = 0;
    while (offset < frames.len) {
        const user_len: usize = @as(usize, frames[offset + 2]) - 5;
        const blocks = if (user_len == 0) 0 else std.math.divCeil(usize, user_len, link.max_block_len) catch unreachable;
        const frame_len = link.header_frame_len + user_len + blocks * link.crc_len;
        if (try session.feedFrame(frames[offset..][0..frame_len], 100, &out)) |_| replies += 1;
        offset += frame_len;
    }
    try testing.expect(offset > link.maxFrameLen(transport.max_segment_payload)); // really split
    try testing.expectEqual(@as(usize, 1), replies);
}

test "Session: a transport segment out of order is a typed error, not a crash" {
    var fix = Fixture{};
    var station = fix.station(.{ .address = 10, .master_address = 1 });
    var rx: [512]u8 = undefined;
    var scratch: [256]u8 = undefined;
    var tx: [512]u8 = undefined;
    var session = Session.init(&station, &rx, &scratch, &tx);
    var out: [512]u8 = undefined;
    var frame_buf: [128]u8 = undefined;

    const control = link.Control{
        .dir = true,
        .prm = true,
        .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data),
    };
    // FIR, seq 0, not FIN.
    const first = try link.encodeFrame(control, 10, 1, &.{ 0x40, 0xC0, 0x01 }, &frame_buf);
    try testing.expectEqual(@as(?[]u8, null), try session.feedFrame(first, 100, &out));

    // The next segment should be seq 1; hand it seq 5.
    var frame_buf2: [128]u8 = undefined;
    const wrong = try link.encodeFrame(control, 10, 1, &.{ 0x85, 0x3C, 0x01, 0x06 }, &frame_buf2);
    try testing.expectError(error.SequenceMismatch, session.feedFrame(wrong, 200, &out));

    // A continuation with no FIR before it.
    var session2 = Session.init(&station, &rx, &scratch, &tx);
    const orphan = try link.encodeFrame(control, 10, 1, &.{ 0x81, 0x01 }, &frame_buf2);
    try testing.expectError(error.UnexpectedContinuation, session2.feedFrame(orphan, 300, &out));
}

test "Session: a frame with a bad CRC is a typed error" {
    var fix = Fixture{};
    var station = fix.station(.{ .address = 10, .master_address = 1 });
    var rx: [512]u8 = undefined;
    var scratch: [256]u8 = undefined;
    var tx: [512]u8 = undefined;
    var session = Session.init(&station, &rx, &scratch, &tx);
    var out: [512]u8 = undefined;
    var frame_buf: [64]u8 = undefined;

    const good = try link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data) },
        10,
        1,
        &.{ 0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06 },
        &frame_buf,
    );
    var corrupt: [64]u8 = undefined;
    @memcpy(corrupt[0..good.len], good);
    corrupt[9] ^= 0x01; // flip a header CRC bit
    try testing.expectError(error.BadHeaderCrc, session.feedFrame(corrupt[0..good.len], 100, &out));
}

// ── hostile input ───────────────────────────────────────────────────────────

test "hostile: a fragment that is not FIR+FIN is PARAMETER_ERROR" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;

    // FIR without FIN.
    const fir_only = [_]u8{ 0x80, 0x01, 60, 1, 0x06 };
    var reply = (try station.handle(&fir_only, 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);

    // FIN without FIR.
    const fin_only = [_]u8{ 0x40, 0x01, 60, 1, 0x06 };
    reply = (try station.handle(&fin_only, 200, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);

    // Neither.
    const neither = [_]u8{ 0x00, 0x01, 60, 1, 0x06 };
    reply = (try station.handle(&neither, 300, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);
}

test "hostile: a short or empty fragment is a response, not a crash" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;

    var reply = (try station.handle(&.{}, 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);
    reply = (try station.handle(&.{0xC0}, 200, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);
    // A bare header with no objects: a valid (if pointless) READ.
    reply = (try station.handle(&.{ 0xC0, 0x01 }, 300, &out)).?;
    try testing.expectEqual(FunctionCode.response, (try application.decodeResponseHeader(reply.fragment)).header.function);
}

test "hostile: a command whose object count overruns the fragment is PARAMETER_ERROR" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var out: [256]u8 = undefined;

    // g12v1, count 5, but only one CROB actually present.
    var req: [64]u8 = undefined;
    var pos = (try application.encodeRequestHeader(
        .{ .control = .{ .fir = true, .fin = true, .seq = 0 }, .function = .direct_operate },
        &req,
    )).len;
    pos += (try objects.encodeObjectHeader(.{
        .group = 12,
        .variation = 1,
        .qualifier = .{ .prefix_code = .index_1b, .range_code = .count_1b },
        .range = .{ .count = 5 },
    }, req[pos..])).len;
    req[pos] = 0;
    pos += 1;
    pos += (try (objects.g12.V1{
        .control_code = .{ .op_type = .latch_on },
        .count = 1,
        .on_time_ms = 0,
        .off_time_ms = 0,
    }).encode(req[pos..])).len;

    const reply = (try station.handle(req[0..pos], 100, &out)).?;
    try testing.expect((try responseIin(reply.fragment)).parameter_error);
}

test "hostile: a tiny output buffer is a typed error, not a stomp" {
    var fix = Fixture{};
    var station = fix.station(.{});
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, station.handle(&.{ 0xC0, 0x01, 60, 1, 0x06 }, 100, &tiny));
}

test "fuzz: random request fragments never panic and always resolve" {
    var fix = Fixture{};
    var station = fix.station(.{
        .select_timeout_ms = 1000,
        .unsolicited_supported = true,
        .allow_restart = true,
    });
    var out: [2048]u8 = undefined;
    var fragment: [300]u8 = undefined;

    var state: u32 = 0x51E7A3C9;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const len = state % (fragment.len + 1);
        for (fragment[0..len]) |*b| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b.* = @truncate(state);
        }
        const maybe = station.handle(fragment[0..len], i * 7, &out) catch |err| {
            try testing.expectEqual(error.BufferTooSmall, err);
            continue;
        };
        if (maybe) |reply| {
            // Whatever came out must be a decodable response fragment.
            const decoded = try application.decodeResponseHeader(reply.fragment);
            try testing.expect(decoded.header.function == .response or
                decoded.header.function == .unsolicited_response);
        }
        // Drain any half-finished multi-fragment response.
        while (station.cursor != null) {
            _ = station.next(i * 7, &out) catch break;
        }
    }
}

test "fuzz: random link frames through a Session never panic" {
    var fix = Fixture{};
    var station = fix.station(.{ .address = 10, .master_address = 1 });
    var rx: [1024]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx: [1024]u8 = undefined;
    var session = Session.init(&station, &rx, &scratch, &tx);
    var out: [2048]u8 = undefined;
    var frame: [400]u8 = undefined;

    var state: u32 = 0x2B7E1516;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const len = state % (frame.len + 1);
        // Half the frames start with the real 0x0564 start bytes, so the
        // fuzzer gets past the first check often enough to be useful.
        for (frame[0..len]) |*b| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b.* = @truncate(state);
        }
        if (len >= 2 and state & 1 == 0) {
            frame[0] = link.start0;
            frame[1] = link.start1;
        }
        _ = session.feedFrame(frame[0..len], i * 3, &out) catch {};
    }
}

test "meta: the module reports both roles" {
    const root = @import("root.zig");
    try testing.expectEqual(.both, root.meta.role);
}
