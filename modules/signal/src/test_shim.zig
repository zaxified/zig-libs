// SPDX-License-Identifier: MIT

//! Test-only by-value adapters over the pointer / out-parameter API. The
//! public secret-handling entry points take secrets by `*const` and return
//! them through `out` (so no copy sits in a returned-by-value temporary, see
//! `burn.zig`); the KAT, the in-file tests and the constant-time harness are
//! easier to read with values. Never imported outside tests / the harness.

const std = @import("std");
const x3 = @import("x3dh.zig");
const pq = @import("pqxdh.zig");
const xed = @import("xeddsa.zig");
const rat = @import("ratchet.zig");

pub const x3dh = struct {
    pub fn generateKeyPair(io: std.Io) std.crypto.dh.X25519.KeyPair {
        var kp: std.crypto.dh.X25519.KeyPair = undefined;
        x3.generateKeyPair(io, &kp);
        return kp;
    }

    pub fn generateSignedPreKey(bob_ik: x3.IdentityKey, id: u32, z: xed.RandomData, io: std.Io) x3.SignedPreKey {
        var out: x3.SignedPreKey = undefined;
        x3.generateSignedPreKey(&bob_ik, id, z, io, &out);
        return out;
    }

    pub fn initiateUnverified(allocator: std.mem.Allocator, alice_ik: x3.IdentityKey, bundle: x3.PreKeyBundle, pt: []const u8, io: std.Io) (x3.AgreementError || std.mem.Allocator.Error)!x3.InitiateOutput {
        var out: x3.InitiateOutput = undefined;
        try x3.initiateUnverified(allocator, &alice_ik, bundle, pt, io, &out);
        return out;
    }

    pub fn initiate(allocator: std.mem.Allocator, alice_ik: x3.IdentityKey, bundle: x3.PreKeyBundle, pt: []const u8, io: std.Io) (x3.InitiateError || std.mem.Allocator.Error)!x3.InitiateOutput {
        var out: x3.InitiateOutput = undefined;
        try x3.initiate(allocator, &alice_ik, bundle, pt, io, &out);
        return out;
    }

    pub fn respond(allocator: std.mem.Allocator, bob_ik: x3.IdentityKey, bob_spk: x3.SignedPreKey, bob_opk: ?x3.OneTimePreKey, initial: x3.InitialMessage) x3.RespondError!x3.RespondOutput {
        var out: x3.RespondOutput = undefined;
        try x3.respond(allocator, &bob_ik, &bob_spk, if (bob_opk) |*o| o else null, initial, &out);
        return out;
    }
};

pub const pqxdh = struct {
    pub fn generateKemPreKey(bob_ik: x3.IdentityKey, id: u32, last_resort: bool, z: xed.RandomData, io: std.Io) pq.KemPreKey {
        var out: pq.KemPreKey = undefined;
        pq.generateKemPreKey(&bob_ik, id, last_resort, z, io, &out);
        return out;
    }

    pub fn initiateUnverified(allocator: std.mem.Allocator, alice_ik: x3.IdentityKey, bundle: pq.PreKeyBundle, pt: []const u8, io: std.Io) (pq.InitiateError || std.mem.Allocator.Error)!pq.InitiateOutput {
        var out: pq.InitiateOutput = undefined;
        try pq.initiateUnverified(allocator, &alice_ik, bundle, pt, io, &out);
        return out;
    }

    pub fn initiate(allocator: std.mem.Allocator, alice_ik: x3.IdentityKey, bundle: pq.PreKeyBundle, pt: []const u8, io: std.Io) (pq.InitiateError || std.mem.Allocator.Error)!pq.InitiateOutput {
        var out: pq.InitiateOutput = undefined;
        try pq.initiate(allocator, &alice_ik, bundle, pt, io, &out);
        return out;
    }

    pub fn respond(allocator: std.mem.Allocator, bob_ik: x3.IdentityKey, bob_spk: x3.SignedPreKey, bob_opk: ?x3.OneTimePreKey, bob_kem: pq.KemPreKey, initial: pq.InitialMessage) pq.RespondError!pq.RespondOutput {
        var out: pq.RespondOutput = undefined;
        try pq.respond(allocator, &bob_ik, &bob_spk, if (bob_opk) |*o| o else null, &bob_kem, initial, &out);
        return out;
    }
};

pub const xeddsa = struct {
    pub fn sign(priv: [32]u8, msg: []const u8, z: xed.RandomData) xed.Signature {
        return xed.sign(&priv, msg, z);
    }

    pub const libsignal = struct {
        pub fn sign(priv: [32]u8, msg: []const u8, z: xed.RandomData) xed.Signature {
            return xed.libsignal.sign(&priv, msg, z);
        }
    };
};

pub const State = struct {
    pub fn initAlice(sk: [32]u8, ad: [rat.associated_data_length]u8, bob_pub: [32]u8, io: std.Io) rat.AgreementError!rat.State {
        var out: rat.State = undefined;
        try rat.State.initAlice(&sk, ad, bob_pub, io, &out);
        return out;
    }

    pub fn initBob(sk: [32]u8, ad: [rat.associated_data_length]u8, kp: std.crypto.dh.X25519.KeyPair) rat.State {
        var out: rat.State = undefined;
        rat.State.initBob(&sk, ad, &kp, &out);
        return out;
    }
};
