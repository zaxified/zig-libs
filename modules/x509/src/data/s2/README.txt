corpus.bin: differential corpus for x509 name/EKU/root handling; each record holds a chain, a mode and Go crypto/x509's verdict (go_ok).
Regenerate (needs python3 cryptography, openssl, go): PYTHONDONTWRITEBYTECODE=1 python3 modules/x509/tools/gen_names_fixtures.py
Format: see the comment block "corpus.bin FORMAT" near the top of modules/x509/tools/gen_names_fixtures.py.
Deterministic except signature randomness (EC keys derived from fixed integers; the O-sha1 cases use fresh RSA keys).
Replayed by a Zig test through x509.verifyChain / hostname matching; O-parse cases are not included.
Format v2 (magic X509S2\0\2): every record carries the caller's acceptable policy set (u8 n_policies, then len-prefixed DER OID contents; Go VerifyOptions.CertificatePolicies) before go_ok. The pol2-* cases (probe O-policy2) cover RFC 5280 policy processing: mappings, policyConstraints, inhibitAnyPolicy, self-issued intermediates, caller policy sets, malformed policy extensions.
