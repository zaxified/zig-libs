// SPDX-License-Identifier: MIT

//! What a wallet's "send to" field does with `btcaddr`: take the address a
//! user pasted, refuse it unless it pays on the wallet's network, turn it into
//! the scriptPubKey the transaction output needs, and show it back — then
//! import a WIF private key the same way.
//!
//! Built by `zig build check-examples` against the published module only.
//! No allocator: the module allocates nowhere.
//!
//! Every vector here is a row of Bitcoin Core's `key_io_valid.json` (MIT),
//! the file the module's own tests replay in full; this example uses a few
//! of them the way a caller would, not as a test table.

const std = @import("std");
const btcaddr = @import("btcaddr");

const Payee = struct { address: []const u8, script_hex: []const u8, kind: btcaddr.ScriptKind };

const payees = [_]Payee{
    .{ .address = "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo", .script_hex = "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac", .kind = .p2pkh },
    .{ .address = "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm", .script_hex = "a914373b819a068f32b7a6b38b6b38729647cfde01c287", .kind = .p2sh },
    .{ .address = "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv", .script_hex = "00146100fc6343edc8c874496cb2f5bbfec88ea9b77c", .kind = .p2wpkh },
    .{ .address = "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu", .script_hex = "51203c671ef1e3913f94980a9e146ba895908550ef4234abb7503d436521aba54c75", .kind = .p2tr },
};

pub fn main() !void {
    // ── send-to field: address -> scriptPubKey, on mainnet only ──
    for (payees) |p| {
        const d = try btcaddr.toScriptPubKeyFor(p.address, .mainnet);
        var want: [64]u8 = undefined;
        const script = try std.fmt.hexToBytes(&want, p.script_hex);
        if (!std.mem.eql(u8, d.script(), script)) return error.WrongScript;
        if (d.kind != p.kind) return error.WrongKind;

        // And back: the confirmation screen shows the canonical address.
        const shown = try btcaddr.fromScriptPubKey(d.script(), .mainnet);
        if (!std.mem.eql(u8, shown.slice(), p.address)) return error.RoundTrip;
        std.debug.print("pay {s:<7} {s}\n", .{ @tagName(d.kind), shown.slice() });
    }

    // A testnet address pasted into a mainnet wallet is refused by name.
    const testnet_taproot = "tb1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aqk3s6gz";
    if (btcaddr.toScriptPubKeyFor(testnet_taproot, .mainnet)) |_| {
        return error.TestnetAcceptedOnMainnet;
    } else |e| switch (e) {
        error.WrongNetwork => std.debug.print("refused on mainnet: {s} (WrongNetwork)\n", .{testnet_taproot}),
        else => return e,
    }
    // The same string decodes, and says which chains it is valid on.
    const tb = try btcaddr.toScriptPubKey(testnet_taproot);
    if (!tb.chains.contains(.testnet) or !tb.chains.contains(.signet) or tb.chains.contains(.mainnet))
        return error.WrongChains;

    // ── key import: WIF -> 32-byte key, compressed flag, and back ──
    const wif = "L5nJeqKmpHp4P7F8ZYyjwc5a7P4d8EabuGAzfGJk7yC1BJyzNaEd";
    var key = try btcaddr.wifDecode(wif);
    defer key.wipe();
    var want_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_key, "ff778740f88ddcf102aeb81daee289c044c4a4571c4b6f287400f4b8e0b843f8");
    if (!std.mem.eql(u8, &key.key, &want_key) or !key.compressed or !key.chains.contains(.mainnet))
        return error.WrongKey;
    var out: [btcaddr.max_wif_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    const again = try btcaddr.wifEncode(&key.key, key.compressed, .mainnet, &out);
    if (!std.mem.eql(u8, again, wif)) return error.WifRoundTrip;
    std.debug.print("imported a compressed mainnet key and re-exported it identically\n", .{});

    // A zero scalar is not a key; the encoder says so instead of emitting one.
    const zero = [_]u8{0} ** 32;
    if (btcaddr.wifEncode(&zero, true, .mainnet, &out)) |_| {
        return error.ZeroKeyEncoded;
    } else |e| switch (e) {
        error.InvalidKey => std.debug.print("refused to encode the zero key (InvalidKey)\n", .{}),
        else => return e,
    }
}
