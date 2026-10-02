// SPDX-License-Identifier: MIT

//! What an outsourced-policy evaluator does with `tfhe`: run a boolean
//! circuit on a client's encrypted inputs, on a machine that is never allowed
//! to learn them, and return an encrypted answer only the client can open.
//!
//! The reason to reach for TFHE rather than the sibling leveled `bfv` is
//! depth: every gate here ends in a bootstrap, which re-decodes the message
//! and emits a FRESH low-noise ciphertext, so the circuit can be as deep as
//! the policy needs and nobody has to size a noise budget in advance. The
//! cost is that a gate is a fraction of a second, not nanoseconds.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("tfhe")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! The parameter set is tfhe-rs's `DEFAULT_PARAMETERS` (`params.tfhers_default`),
//! for which tfhe-rs states 128-bit security and a gate failure probability of
//! at most 2^-64. The keys and ciphertexts below are the same objects tfhe-rs
//! would produce for them (`src/interop_test.zig`).

const std = @import("std");
const tfhe = @import("tfhe");

/// The parameter set. `Tfhe` is generic over it.
const Fhe = tfhe.Tfhe(tfhe.params.tfhers_default);

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Every production key-generation and encryption entry point draws
    // through `std.Io`: a predictable stream here does not weaken LWE, it
    // dissolves it — `n` ciphertexts recover the secret key by Gaussian
    // elimination — so the seeded twins are all suffixed `…ForTest`. The
    // consequence for a consumer is this block: an I/O implementation is
    // required even though nothing below touches a file or a socket.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io: std.Io = threaded.io();

    // ── the rejection a caller must handle ───────────────────────────────
    // Anyone tuning parameters hits this first. `validate` names the specific
    // structural fault, which is what makes it actionable rather than a wrong
    // answer three thousand gates later. NOT a security check.
    var tuned = tfhe.params.tfhers_default;
    tuned.ell = 4; // 10 bits x 4 levels = 40 > 32: the gadget no longer fits
    if (tuned.validate()) |_| {
        return error.BadGadgetAccepted;
    } else |err| switch (err) {
        error.BadGgswGadget => std.debug.print("rejected a gadget wider than the torus\n", .{}),
        else => return err,
    }

    // ── client: keys ─────────────────────────────────────────────────────
    // The client key (two secret keys) stays with the client. The server key
    // — a bootstrap key and a key-switch key, both ENCRYPTIONS of secret
    // material — goes to the evaluator. It is ~78 MB, which is why it lives
    // on the heap and why it travels as bytes.
    var client = Fhe.ClientKey.generate(io);
    defer client.deinit();
    var server_key_bytes: std.Io.Writer.Allocating = .init(gpa);
    defer server_key_bytes.deinit();
    {
        var sk = try Fhe.ServerKey.generate(gpa, &client, io);
        defer sk.deinit(gpa);
        try Fhe.Codec.writeServerKey(&server_key_bytes.writer, &sk);
    }
    std.debug.print("server key: {d} bytes\n", .{server_key_bytes.written().len});

    // ── client: encrypt the policy inputs ────────────────────────────────
    // "is a paid subscriber", "is inside the licensed region", "has a staff
    // override" — three bits the evaluator must not learn.
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    for ([_]bool{ true, false, true }) |b| {
        const ct = client.encrypt(b, io);
        try Fhe.Codec.writeLwe(&wire.writer, &ct);
    }

    // ── evaluator: allowed = subscriber AND (in_region OR override) ───────
    var server = blk: {
        var r: std.Io.Reader = .fixed(server_key_bytes.written());
        break :blk try Fhe.Codec.readServerKey(gpa, &r);
    };
    defer server.deinit(gpa);
    var inputs: std.Io.Reader = .fixed(wire.written());
    const subscriber = try Fhe.Codec.readLwe(&inputs);
    const in_region = try Fhe.Codec.readLwe(&inputs);
    const override = try Fhe.Codec.readLwe(&inputs);
    const where = server.@"or"(&in_region, &override);
    const allowed_ct = server.@"and"(&subscriber, &where);
    // A MUX picks between two encrypted answers without learning which.
    const quota = server.mux(&allowed_ct, &Fhe.ServerKey.trivial(true), &override);

    // ── client: decrypt ──────────────────────────────────────────────────
    const allowed = client.decrypt(&allowed_ct);
    std.debug.print("policy evaluated blind: allowed = {}, quota = {}\n", .{ allowed, client.decrypt(&quota) });
    if (!allowed or !client.decrypt(&quota)) return error.GateComputedWrongAnswer;

    // ── unbounded depth ──────────────────────────────────────────────────
    // The point of bootstrapping: the output of a gate is as clean as a fresh
    // encryption, so it can feed the next gate forever. A leveled scheme
    // stops long before this loop does.
    var carried = allowed_ct;
    for (0..4) |_| carried = server.xnor(&carried, &Fhe.ServerKey.trivial(true));
    if (!client.decrypt(&carried)) return error.DepthLostTheMessage;
    std.debug.print("4 more chained gates: message intact\n", .{});

    // ── decoding refuses bytes for another parameter set ─────────────────
    var r: std.Io.Reader = .fixed(wire.written());
    if (tfhe.Tfhe(tfhe.params.tfhers_tfhe_lib).Codec.readLwe(&r)) |_| {
        return error.ForeignCiphertextAccepted;
    } else |err| switch (err) {
        error.ParameterMismatch => std.debug.print("refused a ciphertext made for other parameters\n", .{}),
        else => return err,
    }

    // ── what a caller cannot check ───────────────────────────────────────
    // A ciphertext decrypted under the wrong key, or an evaluation key that
    // was corrupted in transit, yields a bit — just not the right one — and
    // nothing in the API reports it. A deployment that cares must
    // authenticate the keys and ciphertexts itself; FHE hides the data, it
    // does not authenticate it.
    var other = Fhe.ClientKey.generate(io);
    defer other.deinit();
    std.debug.print("under an unrelated key the answer reads {}, with no error\n", .{other.decrypt(&carried)});
}
