// SPDX-License-Identifier: MIT

//! Test-only by-value adapters over the pointer / out-parameter API. The
//! public secret-handling entry points take secrets by `*const` and return
//! them through `out` (so no copy sits in a returned-by-value temporary, see
//! `burn.zig`); the KAT and end-to-end tests and the constant-time harness are
//! easier to read with values. Never imported outside tests / the harness.

const o = @import("root.zig");

pub fn deriveAkeKeyPair(seed: [o.Nseed]u8) error{DeriveKeyPairFailed}!o.AkeKeyPair {
    var out: o.AkeKeyPair = undefined;
    try o.deriveAkeKeyPair(&seed, &out);
    return out;
}

pub fn createRegistrationRequest(password: []const u8, blind: [o.Ns]u8) @import("voprf").BlindError!o.RegistrationRequest {
    return o.createRegistrationRequest(password, &blind);
}

pub fn createRegistrationResponse(
    request: o.RegistrationRequest,
    server_public_key: [o.Npk]u8,
    credential_identifier: []const u8,
    oprf_seed: [o.Nh]u8,
) o.CreateRegistrationResponseError!o.RegistrationResponse {
    return o.createRegistrationResponse(request, server_public_key, credential_identifier, &oprf_seed);
}

pub fn finalizeRegistrationRequest(
    password: []const u8,
    blind: [o.Ns]u8,
    response: o.RegistrationResponse,
    identities: o.Identities,
    envelope_nonce: [o.Nn]u8,
    ksf: o.Ksf,
) o.FinalizeRegistrationError!o.FinalizeRegistrationResult {
    var out: o.FinalizeRegistrationResult = undefined;
    try o.finalizeRegistrationRequest(password, &blind, response, identities, envelope_nonce, ksf, &out);
    return out;
}

pub fn generateKE1(
    password: []const u8,
    blind: [o.Ns]u8,
    client_nonce: [o.Nn]u8,
    client_keyshare_seed: [o.Nseed]u8,
) o.GenerateKE1Error!o.GenerateKE1Result {
    var out: o.GenerateKE1Result = undefined;
    try o.generateKE1(password, &blind, client_nonce, &client_keyshare_seed, &out);
    return out;
}

pub fn generateKE2(
    server_private_key: [o.Nsk]u8,
    server_public_key: [o.Npk]u8,
    record: o.RegistrationRecord,
    credential_identifier: []const u8,
    oprf_seed: [o.Nh]u8,
    ke1: o.KE1,
    identities: o.Identities,
    context: []const u8,
    masking_nonce: [o.Nn]u8,
    server_nonce: [o.Nn]u8,
    server_keyshare_seed: [o.Nseed]u8,
) o.GenerateKE2Error!o.GenerateKE2Result {
    var out: o.GenerateKE2Result = undefined;
    try o.generateKE2(&server_private_key, server_public_key, record, credential_identifier, &oprf_seed, ke1, identities, context, masking_nonce, server_nonce, &server_keyshare_seed, &out);
    return out;
}

pub fn generateKE3(
    state: o.ClientLoginState,
    identities: o.Identities,
    context: []const u8,
    ke2: o.KE2,
    ksf: o.Ksf,
) o.GenerateKE3Error!o.GenerateKE3Result {
    var out: o.GenerateKE3Result = undefined;
    try o.generateKE3(&state, identities, context, ke2, ksf, &out);
    return out;
}

pub fn serverFinish(state: o.ServerLoginState, ke3: o.KE3) o.ClientAuthenticationError![o.Nx]u8 {
    var out: [o.Nx]u8 = undefined;
    try o.serverFinish(&state, ke3, &out);
    return out;
}

pub fn scalarFromWideBytes(wide: [64]u8) [o.Ns]u8 {
    var out: [o.Ns]u8 = undefined;
    o.scalarFromWideBytes(&wide, &out);
    return out;
}
