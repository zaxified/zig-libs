// SPDX-License-Identifier: MIT

//! Test-only by-value adapters over the pointer / out-parameter API. The
//! public secret-handling entry points take secrets by `*const` and return
//! them through `out` (so no copy sits in a returned-by-value temporary, see
//! `burn.zig`); the KAT and unit tests are easier to read with values. Never
//! imported outside tests.

const std = @import("std");
const session = @import("session.zig");
const pickle = @import("pickle.zig");
const session_key = @import("session_key.zig");
const ratchet = @import("ratchet.zig");
const cipher = @import("cipher.zig");

const Out = session.OutboundSession;
const In = session.InboundGroupSession;

pub fn outboundInit(io: std.Io) Out {
    var s: Out = undefined;
    Out.init(io, &s);
    return s;
}

pub fn sessionKey(s: *const Out) !session_key.SessionKey {
    var k: session_key.SessionKey = undefined;
    try s.sessionKey(&k);
    return k;
}

pub fn fromSessionKey(key: session_key.SessionKey) !In {
    var s: In = undefined;
    try In.fromSessionKey(&key, &s);
    return s;
}

pub fn fromExportedKey(key: session_key.ExportedSessionKey) !In {
    var s: In = undefined;
    try In.fromExportedKey(&key, &s);
    return s;
}

pub fn exportAt(s: *In, index: u32) ?session_key.ExportedSessionKey {
    var k: session_key.ExportedSessionKey = undefined;
    return if (s.exportAt(index, &k)) k else null;
}

pub fn outboundFromPickle(bytes: []const u8) pickle.PickleError!Out {
    var s: Out = undefined;
    try Out.fromPickle(bytes, &s);
    return s;
}

pub fn outboundFromSealedPickle(bytes: []const u8, key: *const pickle.PickleKey) pickle.PickleError!Out {
    var s: Out = undefined;
    try Out.fromSealedPickle(bytes, key, &s);
    return s;
}

pub fn inboundFromPickle(bytes: []const u8) pickle.PickleError!In {
    var s: In = undefined;
    try In.fromPickle(bytes, &s);
    return s;
}

pub fn inboundFromSealedPickle(bytes: []const u8, key: *const pickle.PickleKey) pickle.PickleError!In {
    var s: In = undefined;
    try In.fromSealedPickle(bytes, key, &s);
    return s;
}

pub fn ratchetInit(data: *const [ratchet.ratchet_len]u8, counter: u32) ratchet.Ratchet {
    var r: ratchet.Ratchet = undefined;
    ratchet.Ratchet.init(data, counter, &r);
    return r;
}

pub fn ratchetGenerate(io: std.Io) ratchet.Ratchet {
    var r: ratchet.Ratchet = undefined;
    ratchet.Ratchet.generate(io, &r);
    return r;
}

pub fn deriveKeys(ratchet_bytes: *const [ratchet.ratchet_len]u8) cipher.Keys {
    var k: cipher.Keys = undefined;
    cipher.deriveKeys(ratchet_bytes, &k);
    return k;
}

pub fn encodeExported(key: *const session_key.ExportedSessionKey) [session_key.export_len]u8 {
    var out: [session_key.export_len]u8 = undefined;
    key.encode(&out);
    return out;
}

pub fn encodeShared(key: *const session_key.SessionKey) [session_key.share_len]u8 {
    var out: [session_key.share_len]u8 = undefined;
    key.encode(&out);
    return out;
}

pub fn decodeExported(bytes: []const u8) session_key.DecodeError!session_key.ExportedSessionKey {
    var k: session_key.ExportedSessionKey = undefined;
    try session_key.ExportedSessionKey.decode(bytes, &k);
    return k;
}

pub fn decodeShared(bytes: []const u8) session_key.DecodeError!session_key.SessionKey {
    var k: session_key.SessionKey = undefined;
    try session_key.SessionKey.decode(bytes, &k);
    return k;
}

pub fn exportedFromBase64(allocator: std.mem.Allocator, s: []const u8) session_key.FromBase64Error!session_key.ExportedSessionKey {
    var k: session_key.ExportedSessionKey = undefined;
    try session_key.ExportedSessionKey.fromBase64(allocator, s, &k);
    return k;
}

pub fn sessionKeyFromBase64(allocator: std.mem.Allocator, s: []const u8) session_key.FromBase64Error!session_key.SessionKey {
    var k: session_key.SessionKey = undefined;
    try session_key.SessionKey.fromBase64(allocator, s, &k);
    return k;
}
