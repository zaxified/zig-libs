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
