# saml tools

`saml_oracle.py` is the differential oracle for the SP metadata and AuthnRequest
builders (CONVENTIONS §9: an oracle that talks to the module only through its wire
format). It reads the fixtures pinned in `../src/test_metadata.zig` — the bytes the
module's own tests assert `buildSpMetadata` / `buildAuthnRequest` emit — and checks
them against python3-saml 1.16.0 (MIT): OASIS XML Schema validation of every
metadata document and AuthnRequest, xmlsec1 verification of the signed metadata (and
refusal of a tampered copy), and a structural comparison with python3-saml's own
metadata builder. Requirements and the exact command are in the script's docstring.

When a builder's output changes, the pinned fixture in `test_metadata.zig` must be
updated to the new bytes AND this oracle re-run before the change is committed; the
pin is what carries the oracle's verdict into the hermetic test lane.
