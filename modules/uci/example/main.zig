// SPDX-License-Identifier: MIT

//! What an OpenWRT device-config tool does with `uci`: parse a realistic
//! `/etc/config`-shaped file — the awkward parts included (an unnamed
//! `wifi-iface` section, a `list` option, a value with a `#` mid-word that is
//! NOT a comment, and a double-quoted value carrying an escaped quote) — walk
//! it with the typed accessors, resolve `@type[N]` positional addressing the
//! way `uci` CLI syntax does, round-trip it back to canonical text, and see a
//! malformed file rejected by NAME with a 1-based line number.

const std = @import("std");
const uci = @import("uci");

// Modeled on real OpenWRT `/etc/config/wireless` + `/etc/config/firewall`
// shapes: a named `wifi-device`, two anonymous `wifi-iface` sections (the
// normal OpenWRT convention — wifi interfaces are never named), a `list`
// option accumulating three entries, and one value whose `#` is mid-word
// (not a comment) plus a double-quoted value with an escaped `"`.
const device_config =
    \\config wifi-device 'radio0'
    \\    option type 'mac80211'
    \\    option channel '36'
    \\    option htmode 'HE80'
    \\
    \\config wifi-iface
    \\    option device 'radio0'
    \\    option mode 'ap'
    \\    option ssid 'lab-net'
    \\    option key "pass\"word#1"   # trailing comment, not part of the value
    \\    list network 'lan'
    \\
    \\config wifi-iface
    \\    option device 'radio0'
    \\    option mode 'ap'
    \\    option ssid 'guest#open'
    \\    option network 'guest'
    \\
    \\config rule
    \\    option name 'Allow-mDNS'
    \\    option proto 'udp'
    \\    list dest_port '5353'
    \\    list dest_port '5354'
    \\    list dest_port '5355'
    \\
;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    var pkg = try uci.parse(gpa, device_config);
    defer pkg.deinit(gpa);

    // Named section lookup, and the mid-word '#' that must survive as data.
    const radio0 = pkg.section("wifi-device", "radio0").?;
    std.debug.print("radio0: type={s} channel={s}\n", .{ radio0.get("type").?, radio0.get("channel").? });

    // `@type[N]` positional addressing — the two anonymous wifi-iface
    // sections are addressed the same way `uci show wireless.@wifi-iface[1]`
    // does on a real device: first by positive index, then by libuci's
    // negative-from-the-end form.
    const first_iface = pkg.nth("wifi-iface", 0).?;
    const last_iface = pkg.nth("wifi-iface", -1).?;
    std.debug.print("wifi-iface[0].ssid={s}\n", .{first_iface.get("ssid").?});
    std.debug.print("wifi-iface[-1].ssid={s}\n", .{last_iface.get("ssid").?});
    // The double-quote escape decoded correctly: `\"` -> `"`, and the `#`
    // inside the value is literal (only a token-leading `#` starts a
    // comment) — the trailing `# trailing comment` after it was dropped.
    std.debug.print("wifi-iface[0].key={s}\n", .{first_iface.get("key").?});
    if (!std.mem.eql(u8, first_iface.get("key").?, "pass\"word#1")) return error.UnexpectedDecode;

    // A `list` option accumulates in order, distinct from `option` (single).
    var rule_it = pkg.iterate("rule");
    const rule = rule_it.next().?;
    const ports = rule.getList("dest_port");
    std.debug.print("rule ports: {s} {s} {s}\n", .{ ports[0], ports[1], ports[2] });

    // Round-trip: parse -> serialize -> parse must land on an equal model,
    // and the second serialization must be byte-identical to the first —
    // the module's own stability guarantee, exercised on THIS input, not a
    // hand-authored golden only the module's own tests ever see.
    const text1 = try uci.serialize(gpa, &pkg);
    defer gpa.free(text1);
    var reparsed = try uci.parse(gpa, text1);
    defer reparsed.deinit(gpa);
    if (!pkg.eql(&reparsed)) return error.RoundTripMismatch;
    const text2 = try uci.serialize(gpa, &reparsed);
    defer gpa.free(text2);
    if (!std.mem.eql(u8, text1, text2)) return error.SerializationNotStable;
    std.debug.print("round-trip stable: {d} bytes\n", .{text1.len});

    // Negative case: mixing `option` and `list` under one key is a real UCI
    // mistake (a config author who forgot they already declared it as a
    // list) — rejected by name, with the 1-based line number a diagnostic
    // tool needs to report the offending file.
    var diag: uci.Diagnostics = .{};
    const bad = "config t\n\toption k 'v'\n\tlist k 'w'\n";
    if (uci.parseDiag(gpa, bad, &diag)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.MixedOptionList => std.debug.print("rejected mixed option/list at line {d}: MixedOptionList (expected)\n", .{diag.line}),
        else => return err,
    }
}
