// SPDX-License-Identifier: MIT

//! What a TLS 1.3 server engine does with `tlsresume`: issue a session
//! ticket after a full handshake, then — on a later ClientHello offering it
//! back — unseal it, verify the PSK binder and accept the resumption via
//! `selectPsk`. Both sides of the handshake are simulated in this one
//! process (this module never touches a socket or a ClientHello itself —
//! see the module doc comment), using the same RFC 8448 §3/§4 known-answer
//! values `psk.zig`'s own tests are pinned against, so the PSK math here is
//! independently checkable against the published RFC trace.
//!
//! Built against the PUBLISHED module (`@import("tlsresume")`) only.

const std = @import("std");
const tlsresume = @import("tlsresume");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 8448 §3/§4's resumption_master_secret and the ticket_nonce its own
// NewSessionTicket carries — the values this module's `psk.zig` is
// KAT-validated against. Copied here from the published RFC text (not from
// the module's tests) so this example is checkable independently of them.
const rfc8448_rms = hexTo(32, "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");
const rfc8448_ticket_nonce = [_]u8{ 0x00, 0x00 };
// RFC 8448 §4's transcript hash of the truncated (resumed) ClientHello —
// what a real engine would compute over the wire bytes; taken as given here.
const rfc8448_binder_hash = hexTo(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");

fn emptyTranscriptHash() [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash("", &h, .{});
    return h;
}

pub fn main() !void {
    const now_ms: i64 = 1_700_000_000_000;
    const stek_key = [_]u8{0x42} ** tlsresume.stek.key_length;

    var ring: tlsresume.StekRing(3) = .init();
    ring.rotate(1, stek_key, @divTrunc(now_ms, 1000));

    // ── server: issue a ticket after a full handshake ───────────────────
    const State = tlsresume.select.SessionState(32);
    const state: State = .{
        .resumption_master_secret = rfc8448_rms,
        .ticket_nonce = &rfc8448_ticket_nonce,
        .issued_at_ms = now_ms,
        .ticket_age_add = 0x1a2b3c4d,
    };
    var plaintext_buf: [128]u8 = undefined;
    const plaintext = try state.serialize(&plaintext_buf);

    var blob_buf: [128]u8 = undefined;
    const nonce = [_]u8{0xA1} ** tlsresume.stek.nonce_length;
    const sealed_ticket = try ring.seal(plaintext, nonce, &blob_buf);

    var nst_buf: [256]u8 = undefined;
    const nst = try (tlsresume.NewSessionTicket{
        .ticket_lifetime = 7200,
        .ticket_age_add = state.ticket_age_add,
        .ticket_nonce = &rfc8448_ticket_nonce,
        .ticket = sealed_ticket,
    }).encode(&nst_buf);
    std.debug.print("issued NewSessionTicket: {d} bytes (sealed ticket {d} bytes)\n", .{ nst.len, sealed_ticket.len });

    // ── client: presents the ticket on a later connection ───────────────
    // The client derives the same PSK from the ticket_nonce it was given,
    // then the binder over its own truncated ClientHello — this module
    // never sees ClientHello bytes, only the already-hashed transcript.
    const client_psk = tlsresume.psk.derivePsk(Hkdf, rfc8448_rms, &rfc8448_ticket_nonce, 32);
    const client_es = tlsresume.psk.earlySecret(Hkdf, &client_psk);
    const client_binder_key = tlsresume.psk.binderKey(Hkdf, client_es, &emptyTranscriptHash());
    const binder = tlsresume.psk.computeBinder(Hkdf, Hmac, client_binder_key, &rfc8448_binder_hash);

    const actual_age_ms: u32 = 1_500; // time since issuance, per the client's clock
    const identities = [_]tlsresume.select.OfferedIdentity{.{
        .ticket = sealed_ticket,
        .obfuscated_ticket_age = tlsresume.replay.obfuscateAge(actual_age_ms, state.ticket_age_add),
    }};
    const binders = [_][Hmac.mac_length]u8{binder};

    // ── server: unseal + verify + accept (RFC 8446 §4.2.11) ─────────────
    var strike = tlsresume.StrikeRegister.init(std.heap.page_allocator, 16, 10 * std.time.ms_per_min);
    defer strike.deinit();
    var open_scratch: [128]u8 = undefined;

    const selection = try tlsresume.select.selectPsk(
        Hkdf,
        Hmac,
        tlsresume.StekRing(3),
        &ring,
        &identities,
        &binders,
        &emptyTranscriptHash(),
        &rfc8448_binder_hash,
        now_ms + actual_age_ms,
        60_000,
        &strike,
        &open_scratch,
    );
    std.debug.print(
        "resumption accepted: identity[{d}], psk matches RFC 8448 derivation: {}\n",
        .{ selection.selected_index, std.mem.eql(u8, &selection.psk, &client_psk) },
    );

    // A second presentation of the SAME ticket is a replay — the single-use
    // strike register rejects it, and the engine falls back to a full
    // handshake rather than treating this as a fatal error.
    if (tlsresume.select.selectPsk(
        Hkdf,
        Hmac,
        tlsresume.StekRing(3),
        &ring,
        &identities,
        &binders,
        &emptyTranscriptHash(),
        &rfc8448_binder_hash,
        now_ms + actual_age_ms + 10,
        60_000,
        &strike,
        &open_scratch,
    )) |_| {
        return error.ReplayedTicketShouldHaveBeenRejected;
    } else |err| switch (err) {
        error.NoAcceptableIdentity => std.debug.print("replayed ticket rejected by the strike register\n", .{}),
    }
}
