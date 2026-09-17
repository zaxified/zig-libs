// SPDX-License-Identifier: MIT
// Capture a byte-exact cross-implementation oracle for zig-libs'
// `spake2plus.computeW0W1` (audit finding spake2plus F1) from BoringSSL, and
// emit it as a Zig source file of frozen vectors.
//
// The BoringSSL checkout it links against stays OUTSIDE the repo (it is
// built and run, never copied); only this driver and its output live here.
// Run once, commit the output.
//
// Build + run (from a scratch dir holding a BoringSSL build in `boringssl/`):
//   c++ -std=c++17 -O1 -o capture_w0w1 capture_w0w1.cc \
//       -I boringssl -I boringssl/include boringssl/build/libcrypto.a -lpthread
//   ./capture_w0w1 > modules/spake2plus/src/bssl_w0w1_vectors.zig
//
// Two vector sets, both produced by BoringSSL:
//
//   SET A -- the real registration API. `bssl::spake2plus::Register()` is
//   driven end to end over fixed (password, id_prover, id_verifier) triples,
//   yielding w0, w1 and the registration record L. Register derives its own
//   80-byte KDF output internally (scrypt N=32768,r=8,p=1 over the length-
//   prefixed inputs) and does not expose it, so this driver rebuilds the same
//   input with the same public EVP_PBE_scrypt call and PROVES the
//   reconstruction is right by reducing it and requiring the result to equal
//   Register's own w0/w1 (a mismatch aborts). The 80-byte output is what
//   `computeW0W1` takes, so this pins our function against BoringSSL's on
//   inputs that a real SPAKE2+ registration actually produces.
//
//   SET B -- the same reduction, on chosen 80-byte inputs. A scrypt output is
//   a random 320-bit number, so set A never lands anywhere near the modular
//   boundary. Set B drives the exact two lines Register uses
//   (bn_big_endian_to_words + ec_scalar_reduce) on halves equal to 0, 1, n-1,
//   n, n+1, 2^256-1 and 2^320-1, which is where a wide reduction is actually
//   easy to get wrong.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/span.h>

#include "crypto/fipsmodule/ec/internal.h"
#include "crypto/spake2plus/internal.h"

namespace {

constexpr size_t kKdfOutputSize = 80;
constexpr size_t kHalfSize = 40;
constexpr size_t kScalarSize = 32;
constexpr size_t kPointSize = 65;

bssl::Span<const uint8_t> AsBytes(const std::string &s) {
  return bssl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

void Die(const char *msg) {
  fprintf(stderr, "capture_w0w1: %s\n", msg);
  exit(1);
}

// The two lines `Register` uses to turn a 40-byte big-endian half into a
// canonical scalar, run through BoringSSL's own code.
void ReduceHalf(const uint8_t *half, uint8_t out[kScalarSize]) {
  const EC_GROUP *group = EC_group_p256();
  using namespace bssl;
  constexpr size_t kWords = kHalfSize / BN_BYTES;
  BN_ULONG words[kWords];
  bn_big_endian_to_words(words, kWords, half, kHalfSize);
  EC_SCALAR s;
  ec_scalar_reduce(group, &s, words, kWords);
  size_t out_bytes;
  ec_scalar_to_bytes(group, out, &out_bytes, &s);
  if (out_bytes != kScalarSize) {
    Die("unexpected scalar encoding length");
  }
}

// Rebuild the KDF input `Register` builds internally: each of password,
// id_prover, id_verifier prefixed with its length as a u64 little-endian.
std::vector<uint8_t> MhfInput(const std::string &password,
                              const std::string &id_prover,
                              const std::string &id_verifier) {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0)) {
    Die("CBB_init");
  }
  for (const std::string *s : {&password, &id_prover, &id_verifier}) {
    if (!CBB_add_u64le(cbb.get(), s->size()) ||
        !CBB_add_bytes(cbb.get(), AsBytes(*s).data(), s->size())) {
      Die("CBB_add");
    }
  }
  if (!CBB_flush(cbb.get())) {
    Die("CBB_flush");
  }
  return std::vector<uint8_t>(CBB_data(cbb.get()),
                              CBB_data(cbb.get()) + CBB_len(cbb.get()));
}

void PrintHexField(const char *name, const uint8_t *p, size_t n,
                   const char *indent) {
  printf("%s.%s =\n", indent, name);
  for (size_t off = 0; off < n; off += 32) {
    size_t take = n - off < 32 ? n - off : 32;
    printf("%s    \"", indent);
    for (size_t i = 0; i < take; i++) {
      printf("%02x", p[off + i]);
    }
    printf("\"%s\n", off + take == n ? "," : " ++");
  }
}

void EmitSetA(const std::string &password, const std::string &id_prover,
              const std::string &id_verifier, const char *note) {
  uint8_t w0[kScalarSize], w1[kScalarSize], record[kPointSize];
  if (!bssl::spake2plus::Register(
          bssl::Span<uint8_t>(w0, sizeof(w0)),
          bssl::Span<uint8_t>(w1, sizeof(w1)),
          bssl::Span<uint8_t>(record, sizeof(record)), AsBytes(password),
          AsBytes(id_prover), AsBytes(id_verifier))) {
    Die("spake2plus::Register failed");
  }

  // Reconstruct the KDF output Register kept to itself, then prove the
  // reconstruction by reducing it and demanding Register's own answer back.
  std::vector<uint8_t> input = MhfInput(password, id_prover, id_verifier);
  uint8_t kdf[kKdfOutputSize];
  if (!EVP_PBE_scrypt(reinterpret_cast<const char *>(input.data()),
                      input.size(), nullptr, 0, /*N=*/32768, /*r=*/8, /*p=*/1,
                      /*max_mem=*/1024 * 1024 * 33, kdf, sizeof(kdf))) {
    Die("EVP_PBE_scrypt failed");
  }
  uint8_t check0[kScalarSize], check1[kScalarSize];
  ReduceHalf(kdf, check0);
  ReduceHalf(kdf + kHalfSize, check1);
  if (memcmp(check0, w0, kScalarSize) != 0 ||
      memcmp(check1, w1, kScalarSize) != 0) {
    Die("KDF reconstruction disagrees with Register -- vectors NOT emitted");
  }

  printf("    .{\n");
  printf("        .note = \"%s\",\n", note);
  printf("        .password = \"%s\",\n", password.c_str());
  printf("        .id_prover = \"%s\",\n", id_prover.c_str());
  printf("        .id_verifier = \"%s\",\n", id_verifier.c_str());
  PrintHexField("pbkdf_output", kdf, sizeof(kdf), "        ");
  PrintHexField("w0", w0, sizeof(w0), "        ");
  PrintHexField("w1", w1, sizeof(w1), "        ");
  PrintHexField("l", record, sizeof(record), "        ");
  printf("    },\n");
}

// Build an 80-byte input from two 40-byte halves, each given as a 32-byte
// big-endian value in the LOW 32 bytes (top 8 bytes zero) unless `wide` is set,
// in which case the 40 bytes are taken literally.
void PutHalf(uint8_t *dst, const uint8_t *value32) {
  memset(dst, 0, kHalfSize);
  memcpy(dst + (kHalfSize - kScalarSize), value32, kScalarSize);
}

void EmitSetB(const char *note, const uint8_t input[kKdfOutputSize]) {
  uint8_t w0[kScalarSize], w1[kScalarSize];
  ReduceHalf(input, w0);
  ReduceHalf(input + kHalfSize, w1);
  printf("    .{\n");
  printf("        .note = \"%s\",\n", note);
  PrintHexField("pbkdf_output", input, kKdfOutputSize, "        ");
  PrintHexField("w0", w0, sizeof(w0), "        ");
  PrintHexField("w1", w1, sizeof(w1), "        ");
  printf("    },\n");
}

const char kHeader[] =
    "// SPDX-License-Identifier: MIT\n"
    "//! Frozen cross-implementation vectors for `computeW0W1`, captured from\n"
    "//! BoringSSL's SPAKE2+ (`bssl::spake2plus::Register`). Audit finding\n"
    "//! `spake2plus` F1.\n"
    "//!\n"
    "//! RFC 9383 Appendix C states \"the choice of PBKDF is omitted, and values\n"
    "//! for w0 and w1 are provided directly\", so `kat_vectors.zig`'s official\n"
    "//! vector starts *after* `computeW0W1` and cannot exercise it. This file is\n"
    "//! that missing oracle: BoringSSL performs the identical RFC 9383 3.2\n"
    "//! construction -- an 80-byte KDF output split into two 40-byte big-endian\n"
    "//! halves, each wide-reduced mod the P-256 group order -- so its outputs\n"
    "//! pin ours byte for byte.\n"
    "//!\n"
    "//! ## Provenance\n"
    "//!\n"
    "//! * Reference:  BoringSSL `crypto/spake2plus/spake2plus.cc`, commit\n"
    "//!               `922245af6eda11b3f101ab5f542093eb5e7d1a74` (2026-08-07).\n"
    "//! * Licence:    Apache-2.0 (The BoringSSL Authors). Nothing from it is\n"
    "//!               copied or translated into this repo -- it was built, *run*,\n"
    "//!               and its outputs recorded, so no foreign condition attaches\n"
    "//!               here and the root `NOTICE` is unaffected.\n"
    "//! * Driver:     `modules/spake2plus/tools/capture_w0w1.cc` (outside the\n"
    "//!               repo; zig-libs keeps zero external dependencies).\n"
    "//! * Command:    `c++ -std=c++17 -O1 -o capture_w0w1 capture_w0w1.cc \\`\n"
    "//!               `  -I boringssl -I boringssl/include \\`\n"
    "//!               `  boringssl/build/libcrypto.a -lpthread`\n"
    "//!               `./capture_w0w1 > modules/spake2plus/src/bssl_w0w1_vectors.zig`\n"
    "//! * Captured:   2026-08-09.\n"
    "//!\n"
    "//! ## Two sets\n"
    "//!\n"
    "//! `registration` -- `bssl::spake2plus::Register()` driven end to end. It\n"
    "//! derives its own 80-byte KDF output (scrypt N=32768, r=8, p=1 over the\n"
    "//! u64-little-endian length-prefixed password/idProver/idVerifier) and does\n"
    "//! not expose it, so the driver rebuilt that input with the same public\n"
    "//! `EVP_PBE_scrypt` call and required the reduction of the result to equal\n"
    "//! Register's own `w0`/`w1` before emitting anything -- the `pbkdf_output`\n"
    "//! below is therefore provably the one Register used. `l` is Register's\n"
    "//! registration record, an uncompressed SEC1 `w1xP`, which also anchors\n"
    "//! `computeL`.\n"
    "//!\n"
    "//! `boundary` -- the same reduction (BoringSSL's `bn_big_endian_to_words` +\n"
    "//! `ec_scalar_reduce`, the two lines `Register` itself uses) on chosen\n"
    "//! halves: 0, 1, n-1, n, n+1, 2^256-1, 2^320-1. A scrypt output is a random\n"
    "//! 320-bit number and never lands near the modulus, so without these the\n"
    "//! anchor would say nothing about the reduction boundary -- which is the\n"
    "//! part that is easy to get wrong, and the reason a canonical\n"
    "//! `Scalar.fromBytes` (which rejects rather than reduces) is the wrong\n"
    "//! primitive here.\n"
    "//!\n"
    "//! Both sets are plain hex data: the tests that read them run offline, need\n"
    "//! no BoringSSL, and have no skip path.\n"
    "\n"
    "/// One `Register()` run: everything BoringSSL reported for it.\n"
    "pub const Registration = struct {\n"
    "    note: []const u8,\n"
    "    password: []const u8,\n"
    "    id_prover: []const u8,\n"
    "    id_verifier: []const u8,\n"
    "    /// The 80-byte KDF output `Register` reduced (160 hex chars).\n"
    "    pbkdf_output: []const u8,\n"
    "    w0: []const u8,\n"
    "    w1: []const u8,\n"
    "    /// Registration record: uncompressed SEC1 `w1xP`.\n"
    "    l: []const u8,\n"
    "};\n"
    "\n"
    "/// One chosen 80-byte input and the scalars BoringSSL reduces it to.\n"
    "pub const Boundary = struct {\n"
    "    note: []const u8,\n"
    "    pbkdf_output: []const u8,\n"
    "    w0: []const u8,\n"
    "    w1: []const u8,\n"
    "};\n"
    "\n";

}  // namespace

int main() {
  fputs(kHeader, stdout);

  printf("pub const registrations = [_]Registration{\n");
  EmitSetA("password", "client", "server",
           "RFC 9383 3.2 registration, ASCII password + short identities");
  EmitSetA("", "", "",
           "empty password and empty identities (all three length prefixes zero)");
  EmitSetA("correct horse battery staple", "prover@example.com",
           "verifier.example.com",
           "long password and realistic identities");
  printf("};\n\n");

  // n = the P-256 group order.
  static const uint8_t kOrder[kScalarSize] = {
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
      0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

  uint8_t zero[kScalarSize] = {0};
  uint8_t one[kScalarSize] = {0};
  one[kScalarSize - 1] = 1;
  uint8_t n_minus_1[kScalarSize];
  memcpy(n_minus_1, kOrder, kScalarSize);
  n_minus_1[kScalarSize - 1] -= 1;
  uint8_t n_plus_1[kScalarSize];
  memcpy(n_plus_1, kOrder, kScalarSize);
  n_plus_1[kScalarSize - 1] += 1;
  uint8_t all_ff_32[kScalarSize];
  memset(all_ff_32, 0xff, kScalarSize);

  printf("pub const boundaries = [_]Boundary{\n");
  uint8_t buf[kKdfOutputSize];

  memset(buf, 0, sizeof(buf));
  EmitSetB("both halves zero -- w0 and w1 must both reduce to 0", buf);

  PutHalf(buf, zero);
  PutHalf(buf + kHalfSize, one);
  EmitSetB("halves 0 and 1 -- the smallest nonzero scalar survives unchanged",
           buf);

  PutHalf(buf, n_minus_1);
  PutHalf(buf + kHalfSize, kOrder);
  EmitSetB("halves n-1 and n -- n-1 is unchanged, n wraps to 0", buf);

  PutHalf(buf, n_plus_1);
  PutHalf(buf + kHalfSize, all_ff_32);
  EmitSetB("halves n+1 and 2^256-1 -- both exceed a canonical scalar and must "
           "reduce, not be rejected",
           buf);

  memset(buf, 0xff, sizeof(buf));
  EmitSetB("both halves 2^320-1 -- the largest input the format can carry", buf);

  // One half maximal, the other minimal, to catch a swapped/duplicated half.
  memset(buf, 0xff, kHalfSize);
  memset(buf + kHalfSize, 0, kHalfSize);
  buf[kKdfOutputSize - 1] = 2;
  EmitSetB("first half 2^320-1, second half 2 -- asymmetric, catches a "
           "swapped or duplicated half",
           buf);

  printf("};\n");
  return 0;
}
