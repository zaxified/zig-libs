# Recipe for src/testdata/blake2b_param_vectors.tsv: BLAKE2b with a key, a salt,
# a personalisation string and an output size other than 32 bytes, as Python's
# hashlib (OpenSSL's BLAKE2b, used as a black box) computes it.
#
#     python3 -I blake2b_param_vectors.py > ../src/testdata/blake2b_param_vectors.tsv
#
# Columns (hex, an empty field is absent): out_len, key, salt, personal, data, digest.
# The data is the repeating pattern 0, 1, ... 250, 0, ... of the stated length.
import hashlib

def pattern(n):
    return bytes(i % 251 for i in range(n))

print("# hashlib.blake2b (OpenSSL) -- out_len\tkey\tsalt\tpersonal\tdata_len\tdigest")
cases = []
for out_len in (1, 16, 20, 32, 48, 64):
    cases.append((out_len, b"", b"", b"", 0))
    cases.append((out_len, b"", b"", b"", 129))
for key_len in (1, 32, 64):
    for data_len in (0, 1, 127, 128, 129, 1000):
        cases.append((32, bytes(range(1, key_len + 1)), b"", b"", data_len))
cases.append((64, bytes(range(64)), b"", b"", 255))  # the BLAKE2 KAT key and a 255-byte input
cases.append((32, b"", bytes(range(16)), b"", 77))
cases.append((32, b"", b"", bytes(range(100, 116)), 77))
cases.append((48, bytes(range(5)), bytes(range(16)), bytes(range(100, 116)), 300))
cases.append((20, b"", b"salt", b"", 10))      # short salt and personal are zero-padded
cases.append((20, b"", b"", b"pers", 10))
for out_len, key, salt, person, data_len in cases:
    d = hashlib.blake2b(pattern(data_len), digest_size=out_len, key=key, salt=salt, person=person).hexdigest()
    print(f"{out_len}\t{key.hex()}\t{salt.hex()}\t{person.hex()}\t{data_len}\t{d}")
