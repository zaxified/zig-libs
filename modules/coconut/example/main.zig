// SPDX-License-Identifier: MIT

//! What a transit operator does with `coconut`: issue a season pass whose
//! attributes are certified by a committee rather than by one server, and let
//! the gate at the platform check only the one attribute it needs. Three
//! issuing authorities each hold a share of the signing key; any two of them
//! can issue; the passenger's wallet combines their partial credentials into
//! one short pass, and at the gate reveals the zone while the age band stays
//! hidden and the two taps cannot be linked to each other.
//!
//! The example plays every role in turn — dealer, two authorities, the wallet,
//! the gate — because that is the shape of the protocol a caller has to drive.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("coconut")` plus its declared dep `bls12_381`, which is a
//! published module a real consumer can depend on too). If a type needed to
//! call the API is not public, or an error cannot be named from outside, this
//! file stops compiling. The module's own tests cannot notice either, because
//! they live inside it.
//!
//! Two entry points here sample secrets — `keygen` and `proveCredential` — and
//! both take an `std.Io` and draw fail-closed through it. That is deliberate
//! and documented: a seeded key would hand every pass in the system to whoever
//! recovers the seed, and a repeated proving nonce lets a gate that sees two
//! taps extract the hidden attributes. It also means a consumer that otherwise
//! does pure pairing arithmetic must have an I/O instance in hand.

const std = @import("std");
const coconut = @import("coconut");
const bls = @import("bls12_381");

/// How many attributes a pass carries, and the issuing committee's shape.
const attribute_count = 2;
const threshold = 2;
const authority_count = 3;

/// Which attribute is which. The indexes are part of the statement: the gate
/// and the issuer must agree that slot 0 is the zone or the disclosure proves
/// nothing useful.
const zone_index = 0;
const age_band_index = 1;

/// Encode an attribute string as a field element. Coconut signs scalars, not
/// text, so this mapping is the consumer's to define — and to keep stable,
/// since two encodings of "zone:A" are two different attributes.
fn attributeScalar(text: []const u8) bls.Fr {
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(text, &digest, .{});
    return bls.Fr.reduceWide(&digest);
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    // ── setup: public parameters both sides derive independently ─────────
    const parameters = coconut.Parameters.generate(gpa, attribute_count) catch |err| switch (err) {
        error.OutOfMemory => return err,
        // A configuration that asks for a zero-attribute credential is a
        // deployment mistake, and it is named rather than an assertion.
        error.NoAttributes => {
            std.debug.print("a credential needs at least one attribute\n", .{});
            return;
        },
    };
    defer parameters.deinit(gpa);

    // ── the dealer: split the committee's signing key ────────────────────
    var committee = coconut.keygen(gpa, io, attribute_count, threshold, authority_count) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidThreshold => {
            std.debug.print("threshold configuration is impossible ({d}-of-{d})\n", .{ threshold, authority_count });
            return;
        },
        else => return err,
    };
    defer committee.deinit(gpa);
    std.debug.print("committee: {d}-of-{d} over {d} attributes\n", .{ threshold, authority_count, attribute_count });

    // ── the gate: derive the committee's aggregate verification key ──────
    // Public shares only. Any `threshold` of them Lagrange-combine to the same
    // key, so a gate that talked to a different pair of authorities gets an
    // identical answer — which is what makes the committee replaceable.
    const gate_vk = try coconut.aggregateVerificationKeys(gpa, committee.vk_shares[0..threshold]);
    defer gate_vk.deinit(gpa);

    // ── the passenger's attributes ───────────────────────────────────────
    var attributes: [attribute_count]bls.Fr = undefined;
    attributes[zone_index] = attributeScalar("zone:A-B");
    attributes[age_band_index] = attributeScalar("age-band:60+");

    // Every authority must sign over the SAME base point, and it is derived
    // from the attribute commitment, not chosen — otherwise the partials
    // cannot be combined at all.
    const base = parameters.commonBase(&attributes);

    // ── two authorities issue, independently ─────────────────────────────
    var partials: [threshold]coconut.PartialCredential = undefined;
    for (committee.sk_shares[0..threshold], &partials) |share, *out| {
        out.* = coconut.signPartial(share, base, &attributes) catch |err| switch (err) {
            // An authority handed an attribute vector of the wrong width
            // refuses rather than signing something it cannot interpret.
            error.MismatchedAttributes => {
                std.debug.print("authority {d}: attribute count does not match its key share\n", .{share.index});
                return;
            },
            else => return err,
        };
        // A partial credential crosses a network, so it round-trips bytes.
        const wire = out.toBytes();
        std.debug.print("authority {d} issued a {d}-byte partial\n", .{ share.index, wire.len });
        _ = try coconut.PartialCredential.fromBytes(wire);
    }

    // ── the wallet: combine into one pass ────────────────────────────────
    const pass = try coconut.aggregateCredential(gpa, &partials, threshold);

    // The wallet checks what it was given before relying on it: a pass that
    // does not verify now is one that will be refused at the gate.
    if (!coconut.psVerifyPlain(gate_vk, pass, &attributes)) {
        return error.IssuedCredentialRejected;
    }
    std.debug.print("wallet holds a {d}-byte pass\n", .{coconut.Credential.encoded_bytes});

    // ── the gate: show only the zone ─────────────────────────────────────
    var disclosed: [attribute_count]bool = @splat(false);
    disclosed[zone_index] = true;

    const proof = try coconut.proveCredential(gpa, io, parameters, gate_vk, pass, &attributes, &disclosed);
    defer proof.deinit(gpa);

    const disclosed_values = [_]bls.Fr{attributes[zone_index]};
    if (!try coconut.verifyCredential(gpa, parameters, gate_vk, proof, &disclosed_values)) {
        return error.HonestShowRejected;
    }
    std.debug.print("gate accepted: zone shown, age band not revealed\n", .{});

    // Two taps produce two unlinkable proofs: the credential is re-randomised
    // on every show, so the bytes differ even though the pass does not.
    const second_tap = try coconut.proveCredential(gpa, io, parameters, gate_vk, pass, &attributes, &disclosed);
    defer second_tap.deinit(gpa);
    const first_bytes = try proof.toBytes(gpa);
    defer gpa.free(first_bytes);
    const second_bytes = try second_tap.toBytes(gpa);
    defer gpa.free(second_bytes);
    if (std.mem.eql(u8, first_bytes, second_bytes)) return error.ShowsAreLinkable;
    std.debug.print("second tap is byte-different: shows are unlinkable\n", .{});

    // ── the rejections a gate must handle ────────────────────────────────
    // 1. The passenger claims a zone the pass does not certify. The proof
    //    commits to the signed value, so a rewritten claim shifts the
    //    Fiat-Shamir challenge and the equations stop closing.
    const lied = [_]bls.Fr{attributeScalar("zone:A-B-C")};
    if (try coconut.verifyCredential(gpa, parameters, gate_vk, proof, &lied)) {
        return error.RewrittenDisclosureAccepted;
    }
    std.debug.print("rewritten zone claim rejected\n", .{});

    // 2. A gate that sends as many values as it sent mask bits. This one IS
    //    an error rather than a false: it is a bug on the verifier's side,
    //    not a failed proof, and the caller has to be able to tell those
    //    apart before logging one as an attack.
    const too_many = [_]bls.Fr{ attributes[zone_index], attributes[age_band_index] };
    if (coconut.verifyCredential(gpa, parameters, gate_vk, proof, &too_many)) |_| {
        return error.MismatchedDisclosureAccepted;
    } else |err| switch (err) {
        error.InvalidDisclosure => std.debug.print("value/mask count mismatch reported as a caller error\n", .{}),
        else => return err,
    }

    // 3. A wallet that reached the threshold only in its own imagination.
    //    One partial is not a credential, and aggregation says so by name
    //    rather than returning a pass that fails later for no clear reason.
    if (coconut.aggregateCredential(gpa, partials[0..1], threshold)) |_| {
        return error.UnderThresholdAccepted;
    } else |err| switch (err) {
        error.NotEnoughPartials => std.debug.print("below-threshold aggregation rejected\n", .{}),
        else => return err,
    }
}
