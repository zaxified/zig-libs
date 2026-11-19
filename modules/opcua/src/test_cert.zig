//! Test-only: a minimal DER certificate shell carrying an RSA public key of
//! a chosen modulus size, for key-length checks that never look past the SPKI.

/// DER certificate shell around an RSAPublicKey with a `bits`-bit odd modulus
/// (top bit set) and e = 65537 — no private key behind it, which is all a
/// peer-certificate key-length check looks at. Returned slice is in `buf`.
pub fn withModulusBits(buf: []u8, bits: usize) []const u8 {
    const k = (bits + 7) / 8;
    // RSAPublicKey { INTEGER n, INTEGER e }: n is k bytes (+1 leading 0x00).
    var n_buf: [1100]u8 = undefined;
    @memset(n_buf[0..k], 0xA5);
    n_buf[0] = @as(u8, 1) << @intCast((bits - 1) % 8);
    n_buf[k - 1] |= 1;
    const tail_len = 19; // signatureAlgorithm + signature, appended last
    var pos: usize = buf.len - tail_len;
    // Build backwards: SPKI pieces are small enough for fixed 2-byte lengths.
    const Der = struct {
        fn put(b: []u8, p: *usize, tag: u8, body_len: usize) void {
            if (body_len < 128) {
                p.* -= 1;
                b[p.*] = @intCast(body_len);
            } else if (body_len < 256) {
                p.* -= 2;
                b[p.*] = 0x81;
                b[p.* + 1] = @intCast(body_len);
            } else {
                p.* -= 3;
                b[p.*] = 0x82;
                b[p.* + 1] = @intCast(body_len >> 8);
                b[p.* + 2] = @intCast(body_len & 0xff);
            }
            p.* -= 1;
            b[p.*] = tag;
        }
    };
    const end = pos;
    // e
    pos -= 3;
    @memcpy(buf[pos..][0..3], &[_]u8{ 1, 0, 1 });
    Der.put(buf, &pos, 0x02, 3);
    // n (leading zero iff the top bit is set)
    const top_set = (n_buf[0] & 0x80) != 0;
    pos -= k;
    @memcpy(buf[pos..][0..k], n_buf[0..k]);
    if (top_set) {
        pos -= 1;
        buf[pos] = 0;
    }
    Der.put(buf, &pos, 0x02, k + @intFromBool(top_set));
    Der.put(buf, &pos, 0x30, end - pos); // RSAPublicKey
    // BIT STRING wrapper: unused-bits octet 0
    pos -= 1;
    buf[pos] = 0;
    Der.put(buf, &pos, 0x03, end - pos);
    // AlgorithmIdentifier rsaEncryption + NULL
    const alg = [_]u8{ 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
    pos -= alg.len;
    @memcpy(buf[pos..][0..alg.len], &alg);
    Der.put(buf, &pos, 0x30, end - pos); // SubjectPublicKeyInfo
    const spki_start = pos;
    // tbsCertificate: version [0] 2, serial 1, sigalg, issuer, validity, subject, SPKI
    const head = [_]u8{
        0xa0, 0x03, 0x02, 0x01, 0x02, // version v3
        0x02, 0x01, 0x01, // serial
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, // sha256WithRSA
        0x30, 0x00, // issuer
        0x30, 0x1e, 0x17, 0x0d, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z', 0x17, 0x0d, '2', '7', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z', // validity
        0x30, 0x00, // subject
    };
    pos -= head.len;
    @memcpy(buf[pos..][0..head.len], &head);
    Der.put(buf, &pos, 0x30, end - pos); // tbsCertificate
    // signatureAlgorithm + signature (never checked by the key-length gate)
    const tail = [tail_len]u8{ 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x02, 0x00, 0x00 };
    // Certificate = SEQUENCE { tbs, sigalg, sig }: tbs was built first,
    // so append the tail after it by shifting the tail into place.
    _ = spki_start;
    @memcpy(buf[end..][0..tail.len], &tail);
    const total_body = end - pos + tail.len;
    var hdr: [4]u8 = undefined;
    var hl: usize = 0;
    hdr[0] = 0x30;
    if (total_body < 256) {
        hdr[1] = 0x81;
        hdr[2] = @intCast(total_body);
        hl = 3;
    } else {
        hdr[1] = 0x82;
        hdr[2] = @intCast(total_body >> 8);
        hdr[3] = @intCast(total_body & 0xff);
        hl = 4;
    }
    pos -= hl;
    @memcpy(buf[pos..][0..hl], hdr[0..hl]);
    return buf[pos .. end + tail.len];
}
