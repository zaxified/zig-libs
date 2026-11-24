// SPDX-License-Identifier: MIT

//! Test-only by-value adapters over the pointer / out-parameter API. The
//! public secret-handling entry points take secrets by `*const` and return
//! them through `out` (so no copy sits in a returned-by-value temporary, see
//! `burn.zig`); the KAT and end-to-end tests and the constant-time harness are
//! easier to read with values. Never imported outside tests / the harness.

/// The adapters for any configuration `O` (`opaque.Ristretto255Sha512`,
/// `opaque.P256Sha256`, `opaque.Ristretto255Sha512X25519`).
pub fn ShimFor(comptime O: type) type {
    return struct {
        pub fn deriveAkeKeyPair(seed: [O.Nseed]u8) error{DeriveKeyPairFailed}!O.AkeKeyPair {
            var out: O.AkeKeyPair = undefined;
            try O.deriveAkeKeyPair(&seed, &out);
            return out;
        }

        pub fn createRegistrationRequest(password: []const u8, blind: [O.Ns]u8) !O.RegistrationRequest {
            return O.createRegistrationRequest(password, &blind);
        }

        pub fn createRegistrationResponse(
            request: O.RegistrationRequest,
            server_public_key: [O.Npk]u8,
            credential_identifier: []const u8,
            oprf_seed: [O.Nh]u8,
        ) O.CreateRegistrationResponseError!O.RegistrationResponse {
            return O.createRegistrationResponse(request, server_public_key, credential_identifier, &oprf_seed);
        }

        pub fn finalizeRegistrationRequest(
            password: []const u8,
            blind: [O.Ns]u8,
            response: O.RegistrationResponse,
            identities: O.Identities,
            envelope_nonce: [O.Nn]u8,
            ksf: O.Ksf,
        ) O.FinalizeRegistrationError!O.FinalizeRegistrationResult {
            var out: O.FinalizeRegistrationResult = undefined;
            try O.finalizeRegistrationRequest(password, &blind, response, identities, envelope_nonce, ksf, &out);
            return out;
        }

        pub fn generateKE1(
            password: []const u8,
            blind: [O.Ns]u8,
            client_nonce: [O.Nn]u8,
            client_keyshare_seed: [O.Nseed]u8,
        ) O.GenerateKE1Error!O.GenerateKE1Result {
            var out: O.GenerateKE1Result = undefined;
            try O.generateKE1(password, &blind, client_nonce, &client_keyshare_seed, &out);
            return out;
        }

        pub fn generateKE2(
            server_private_key: [O.Nsk]u8,
            server_public_key: [O.Npk]u8,
            record: O.RegistrationRecord,
            credential_identifier: []const u8,
            oprf_seed: [O.Nh]u8,
            ke1: O.KE1,
            identities: O.Identities,
            context: []const u8,
            masking_nonce: [O.Nn]u8,
            server_nonce: [O.Nn]u8,
            server_keyshare_seed: [O.Nseed]u8,
        ) O.GenerateKE2Error!O.GenerateKE2Result {
            var out: O.GenerateKE2Result = undefined;
            try O.generateKE2(&server_private_key, server_public_key, record, credential_identifier, &oprf_seed, ke1, identities, context, masking_nonce, server_nonce, &server_keyshare_seed, &out);
            return out;
        }

        pub fn generateKE3(
            state: O.ClientLoginState,
            identities: O.Identities,
            context: []const u8,
            ke2: O.KE2,
            ksf: O.Ksf,
        ) O.GenerateKE3Error!O.GenerateKE3Result {
            var out: O.GenerateKE3Result = undefined;
            try O.generateKE3(&state, identities, context, ke2, ksf, &out);
            return out;
        }

        pub fn serverFinish(state: O.ServerLoginState, ke3: O.KE3) O.ClientAuthenticationError![O.Nx]u8 {
            var out: [O.Nx]u8 = undefined;
            try O.serverFinish(&state, ke3, &out);
            return out;
        }

        pub fn scalarFromWideBytes(wide: [O.wide_length]u8) [O.Ns]u8 {
            var out: [O.Ns]u8 = undefined;
            O.scalarFromWideBytes(&wide, &out);
            return out;
        }
    };
}

/// The top-level (ristretto255-SHA512) configuration's adapters.
const Default = ShimFor(@import("root.zig").Ristretto255Sha512);
pub const deriveAkeKeyPair = Default.deriveAkeKeyPair;
pub const createRegistrationRequest = Default.createRegistrationRequest;
pub const createRegistrationResponse = Default.createRegistrationResponse;
pub const finalizeRegistrationRequest = Default.finalizeRegistrationRequest;
pub const generateKE1 = Default.generateKE1;
pub const generateKE2 = Default.generateKE2;
pub const generateKE3 = Default.generateKE3;
pub const serverFinish = Default.serverFinish;
pub const scalarFromWideBytes = Default.scalarFromWideBytes;
