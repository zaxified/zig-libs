// SPDX-License-Identifier: MIT
//! SP metadata generation (`buildSpMetadata`) and the AuthnRequest options
//! (`ForceAuthn`, `IsPassive`, `ProtocolBinding`, `AttributeConsumingServiceIndex`,
//! `RequestedAuthnContext`).
//!
//! ANCHOR (EXTERNAL): every `*_xml` constant below is byte-for-byte what the
//! builder emits for the options next to it (asserted here), and each was
//! checked OFFLINE by `tools/saml_oracle.py`:
//!   - the metadata documents validate against OASIS
//!     `saml-schema-metadata-2.0.xsd`, and the AuthnRequests against
//!     `saml-schema-protocol-2.0.xsd` (the copies python3-saml 1.16.0 bundles,
//!     via lxml/libxml2), and python3-saml's own
//!     `OneLogin_Saml2_Utils.validate_xml` accepts them;
//!   - `signed_md_xml`'s enveloped signature verifies under xmlsec1 (python
//!     `xmlsec` 1.3.17, via python3-saml's `validate_metadata_sign`) with
//!     `sp_cert_der_b64`, and a one-byte tamper of it is refused;
//!   - the element/attribute structure is compared against python3-saml's own
//!     `OneLogin_Saml2_Metadata.builder` output for the same settings.
//! Nothing here reproduces the oracle's verdict at test time; the pin is
//! what carries it: a change to the emitted bytes fails these tests and
//! means re-running the oracle (see `tools/README.md`).
//!
//! Test material: the SP key is `test_encrypted_external.sp_priv_pem` (test
//! only); `sp_cert_der_b64` is a self-signed certificate for it made with
//! `openssl req -x509 -new -key sp.key -sha256 -subj /CN=sp.example.org
//! -set_serial 1 -days 36500`. Its DER is never parsed by this module.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const xml = @import("xml");
const xmldsig = @import("xmldsig");
const rsa = @import("rsa");
const ext = @import("test_encrypted_external.zig");

pub const sp_cert_der_b64 = "MIIDAjCCAeqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5zcC5leGFtcGxlLm9yZzAgFw0yNjEwMDYxMDUyMTFaGA8yMTI2MDkxMjEwNTIxMVowGTEXMBUGA1UEAwwOc3AuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLF3y7pbHUCljuahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIGfPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMFZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Djl27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSbamPm7mB8DAgMBAAGjUzBRMB0GA1UdDgQWBBRqrMJrc2XetuFSVnOSwBxJuFAziTAfBgNVHSMEGDAWgBRqrMJrc2XetuFSVnOSwBxJuFAziTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBKMlISpECHQCtxFh0LVdgQgM+S1EDfGwctEpk3XrXSelnLXIB7kjFuRojnEFW8HyaqBZrE+5HX0YQJNzE7Ar8MO7mpcyPJaEwXjtA2mYMEjMmUuX53ETlbu5JQCATzWAEQhqIMHpu0mS08/31W8XxXRk18C9NRpqFrqx8Ci+Pmnae5abP4v0Ah0ApYIRcJqKnS4r6pOuMRyq0itUoN/GE7nCsEacJQC552SmoklBwY1ezV+CLmwBpULc11FqqFbuFiW6b9F60NMN9vFUeCkzc06MC8tg8NfSQn7lzDsk8Ob9lHiU1lUvRHat+EolMgDj1eg3mOeAp52i9rCeH/5+BN";

/// The public half of `ext.sp_priv_pem` (`openssl pkey -pubout`).
const sp_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyxd8u6Wx1ApY7moYV28X
    \\l26Pqssb44LUTSGDY6wNWfmqwd2MTcY0knMP8GaDB++aqxrqcSNTny2CBnz4K5e/
    \\VJat/JmHakwjOrbnyEN8iKsbHMn5RiPlRS7jwyzMZGlsgYQ1mjlVvyyo2vFlNtOS
    \\RHELrgeoN2aP68M1uKN/TTje0RWnqIY033ucwnTgfb25G+CqgcHvZxoTBWYi9qOZ
    \\axCsMkVlb03y3/HBrJC+nME1FUv1SFBW0pnqbdbpH+VvUx97SM9qqluQ45du3Q9E
    \\sFmlzbfjllrxCCzkgDElR5Fwb7vkm8mKnrfwX2dWO2UcaxBR5/aMzoEm2pj5u5gf
    \\AwIDAQAB
    \\-----END PUBLIC KEY-----
;

/// The certificate's DER, decoded at compile time so option structs can point
/// at it statically.
const sp_cert_der: [std.base64.standard.Decoder.calcSizeForSlice(sp_cert_der_b64) catch unreachable]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [std.base64.standard.Decoder.calcSizeForSlice(sp_cert_der_b64) catch unreachable]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, sp_cert_der_b64) catch unreachable;
    break :blk out;
};

// ── pinned, oracle-checked outputs ──────────────────────────────────────────

pub const minimal_md_xml =
    \\<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.org/metadata"><md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>
;
pub const full_md_xml =
    \\<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example.org/metadata?tenant=a&amp;v=2" validUntil="2030-01-01T00:00:00Z" cacheDuration="PT604800S"><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDAjCCAeqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5zcC5leGFtcGxlLm9yZzAgFw0yNjEwMDYxMDUyMTFaGA8yMTI2MDkxMjEwNTIxMVowGTEXMBUGA1UEAwwOc3AuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLF3y7pbHUCljuahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIGfPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMFZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Djl27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSbamPm7mB8DAgMBAAGjUzBRMB0GA1UdDgQWBBRqrMJrc2XetuFSVnOSwBxJuFAziTAfBgNVHSMEGDAWgBRqrMJrc2XetuFSVnOSwBxJuFAziTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBKMlISpECHQCtxFh0LVdgQgM+S1EDfGwctEpk3XrXSelnLXIB7kjFuRojnEFW8HyaqBZrE+5HX0YQJNzE7Ar8MO7mpcyPJaEwXjtA2mYMEjMmUuX53ETlbu5JQCATzWAEQhqIMHpu0mS08/31W8XxXRk18C9NRpqFrqx8Ci+Pmnae5abP4v0Ah0ApYIRcJqKnS4r6pOuMRyq0itUoN/GE7nCsEacJQC552SmoklBwY1ezV+CLmwBpULc11FqqFbuFiW6b9F60NMN9vFUeCkzc06MC8tg8NfSQn7lzDsk8Ob9lHiU1lUvRHat+EolMgDj1eg3mOeAp52i9rCeH/5+BN</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDAjCCAeqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5zcC5leGFtcGxlLm9yZzAgFw0yNjEwMDYxMDUyMTFaGA8yMTI2MDkxMjEwNTIxMVowGTEXMBUGA1UEAwwOc3AuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLF3y7pbHUCljuahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIGfPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMFZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Djl27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSbamPm7mB8DAgMBAAGjUzBRMB0GA1UdDgQWBBRqrMJrc2XetuFSVnOSwBxJuFAziTAfBgNVHSMEGDAWgBRqrMJrc2XetuFSVnOSwBxJuFAziTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBKMlISpECHQCtxFh0LVdgQgM+S1EDfGwctEpk3XrXSelnLXIB7kjFuRojnEFW8HyaqBZrE+5HX0YQJNzE7Ar8MO7mpcyPJaEwXjtA2mYMEjMmUuX53ETlbu5JQCATzWAEQhqIMHpu0mS08/31W8XxXRk18C9NRpqFrqx8Ci+Pmnae5abP4v0Ah0ApYIRcJqKnS4r6pOuMRyq0itUoN/GE7nCsEacJQC552SmoklBwY1ezV+CLmwBpULc11FqqFbuFiW6b9F60NMN9vFUeCkzc06MC8tg8NfSQn7lzDsk8Ob9lHiU1lUvRHat+EolMgDj1eg3mOeAp52i9rCeH/5+BN</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.org/slo"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/slo/post" ResponseLocation="https://sp.example.org/slo/post/response"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0" isDefault="true"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example.org/acs/artifact" index="1"/><md:AttributeConsumingService index="1" isDefault="true"><md:ServiceName xml:lang="en">Example SP</md:ServiceName><md:ServiceDescription xml:lang="en">Staff portal</md:ServiceDescription><md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail" isRequired="true"/><md:RequestedAttribute Name="urn:oid:2.5.4.42" FriendlyName="givenName"/></md:AttributeConsumingService></md:SPSSODescriptor><md:Organization><md:OrganizationName xml:lang="en">Example &amp; Co &lt;SP&gt;</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">Example</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">https://example.org/</md:OrganizationURL></md:Organization><md:ContactPerson contactType="technical"><md:GivenName>Ops</md:GivenName><md:EmailAddress>mailto:ops@example.org</md:EmailAddress></md:ContactPerson><md:ContactPerson contactType="support"><md:Company>Example</md:Company><md:SurName>Desk</md:SurName><md:EmailAddress>mailto:help@example.org</md:EmailAddress><md:TelephoneNumber>+1 555 0100</md:TelephoneNumber></md:ContactPerson></md:EntityDescriptor>
;
pub const signed_md_xml =
    \\<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example.org/metadata?tenant=a&amp;v=2" ID="_sp-metadata.1" validUntil="2030-01-01T00:00:00Z" cacheDuration="PT604800S"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_sp-metadata.1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>cOKWuJYFect9uJlXFRIumc3AN9l/NQAq33mNqk4bDRk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>S7iHb7atRcSwrIYzM0b4GMmulwG6icce2eNK0iEPX5jzYFM5+S+E4ctI8to4kkmRv9Xhutxsb+/ZoGGmuqu1+6xk14zv8n3BNW4bKHLJOZSeRNHNdmO0w94qvnRCmRkrGS22JP9x7ffi+GMK0wK8yzR+13G599hh98u9A/vX5y7cTKLnMhPpWUSou8D2LwQMEPw7wRrkyOgJMCleubfpsV7MKuIZvEcJBkxeaaEY6Wfk7a2cCrHhrk+LPf57TCuhoPUzhZaBzyVKXXe/CLQwEa2Tf/5tnKeJCm1gxv09VCTzczTQo+hwt/n8AD78y6G180F2iylo1mn5WZRCrN3woQ==</ds:SignatureValue></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDAjCCAeqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5zcC5leGFtcGxlLm9yZzAgFw0yNjEwMDYxMDUyMTFaGA8yMTI2MDkxMjEwNTIxMVowGTEXMBUGA1UEAwwOc3AuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLF3y7pbHUCljuahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIGfPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMFZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Djl27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSbamPm7mB8DAgMBAAGjUzBRMB0GA1UdDgQWBBRqrMJrc2XetuFSVnOSwBxJuFAziTAfBgNVHSMEGDAWgBRqrMJrc2XetuFSVnOSwBxJuFAziTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBKMlISpECHQCtxFh0LVdgQgM+S1EDfGwctEpk3XrXSelnLXIB7kjFuRojnEFW8HyaqBZrE+5HX0YQJNzE7Ar8MO7mpcyPJaEwXjtA2mYMEjMmUuX53ETlbu5JQCATzWAEQhqIMHpu0mS08/31W8XxXRk18C9NRpqFrqx8Ci+Pmnae5abP4v0Ah0ApYIRcJqKnS4r6pOuMRyq0itUoN/GE7nCsEacJQC552SmoklBwY1ezV+CLmwBpULc11FqqFbuFiW6b9F60NMN9vFUeCkzc06MC8tg8NfSQn7lzDsk8Ob9lHiU1lUvRHat+EolMgDj1eg3mOeAp52i9rCeH/5+BN</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDAjCCAeqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5zcC5leGFtcGxlLm9yZzAgFw0yNjEwMDYxMDUyMTFaGA8yMTI2MDkxMjEwNTIxMVowGTEXMBUGA1UEAwwOc3AuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLF3y7pbHUCljuahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIGfPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMFZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Djl27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSbamPm7mB8DAgMBAAGjUzBRMB0GA1UdDgQWBBRqrMJrc2XetuFSVnOSwBxJuFAziTAfBgNVHSMEGDAWgBRqrMJrc2XetuFSVnOSwBxJuFAziTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBKMlISpECHQCtxFh0LVdgQgM+S1EDfGwctEpk3XrXSelnLXIB7kjFuRojnEFW8HyaqBZrE+5HX0YQJNzE7Ar8MO7mpcyPJaEwXjtA2mYMEjMmUuX53ETlbu5JQCATzWAEQhqIMHpu0mS08/31W8XxXRk18C9NRpqFrqx8Ci+Pmnae5abP4v0Ah0ApYIRcJqKnS4r6pOuMRyq0itUoN/GE7nCsEacJQC552SmoklBwY1ezV+CLmwBpULc11FqqFbuFiW6b9F60NMN9vFUeCkzc06MC8tg8NfSQn7lzDsk8Ob9lHiU1lUvRHat+EolMgDj1eg3mOeAp52i9rCeH/5+BN</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.org/slo"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/slo/post" ResponseLocation="https://sp.example.org/slo/post/response"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0" isDefault="true"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example.org/acs/artifact" index="1"/><md:AttributeConsumingService index="1" isDefault="true"><md:ServiceName xml:lang="en">Example SP</md:ServiceName><md:ServiceDescription xml:lang="en">Staff portal</md:ServiceDescription><md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail" isRequired="true"/><md:RequestedAttribute Name="urn:oid:2.5.4.42" FriendlyName="givenName"/></md:AttributeConsumingService></md:SPSSODescriptor><md:Organization><md:OrganizationName xml:lang="en">Example &amp; Co &lt;SP&gt;</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">Example</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">https://example.org/</md:OrganizationURL></md:Organization><md:ContactPerson contactType="technical"><md:GivenName>Ops</md:GivenName><md:EmailAddress>mailto:ops@example.org</md:EmailAddress></md:ContactPerson><md:ContactPerson contactType="support"><md:Company>Example</md:Company><md:SurName>Desk</md:SurName><md:EmailAddress>mailto:help@example.org</md:EmailAddress><md:TelephoneNumber>+1 555 0100</md:TelephoneNumber></md:ContactPerson></md:EntityDescriptor>
;
pub const authn_request_default_xml =
    \\<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req_def_01" Version="2.0" IssueInstant="2024-06-01T12:00:00Z" AssertionConsumerServiceURL="https://sp.example.org/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example.org/metadata</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>
;
pub const authn_request_full_xml =
    \\<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req_full_01" Version="2.0" IssueInstant="2024-06-01T12:00:00Z" Destination="https://idp.example.org/sso" ForceAuthn="true" IsPassive="true" AssertionConsumerServiceURL="https://sp.example.org/acs/artifact" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" AttributeConsumingServiceIndex="1"><saml:Issuer>https://sp.example.org/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef><saml:AuthnContextClassRef>http://eidas.europa.eu/LoA/substantial</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>
;

// ── the options that produce them ───────────────────────────────────────────

const minimal_opts: saml.SpMetadataOptions = .{
    .entity_id = "https://sp.example.org/metadata",
    .assertion_consumer_services = &.{.{ .location = "https://sp.example.org/acs", .index = 0 }},
};

fn fullOpts() saml.SpMetadataOptions {
    return .{
        // `&` in the entityID and `<`/`&` in the organization name exercise
        // escaping inside a document the schema validator then accepts.
        .entity_id = "https://sp.example.org/metadata?tenant=a&v=2",
        .assertion_consumer_services = &.{
            .{ .location = "https://sp.example.org/acs", .index = 0, .is_default = true },
            .{ .binding = .http_artifact, .location = "https://sp.example.org/acs/artifact", .index = 1 },
        },
        .single_logout_services = &.{
            .{ .binding = saml.binding_http_redirect, .location = "https://sp.example.org/slo" },
            .{ .binding = saml.binding_http_post, .location = "https://sp.example.org/slo/post", .response_location = "https://sp.example.org/slo/post/response" },
        },
        .name_id_formats = &.{
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        .authn_requests_signed = true,
        .want_assertions_signed = true,
        .signing_certs_der = &.{&sp_cert_der},
        .encryption_certs_der = &.{&sp_cert_der},
        .attribute_consuming_services = &.{.{
            .index = 1,
            .is_default = true,
            .service_names = &.{.{ .value = "Example SP" }},
            .service_descriptions = &.{.{ .value = "Staff portal", .lang = "en" }},
            .requested_attributes = &.{
                .{ .name = "urn:oid:0.9.2342.19200300.100.1.3", .name_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", .friendly_name = "mail", .is_required = true },
                .{ .name = "urn:oid:2.5.4.42", .friendly_name = "givenName" },
            },
        }},
        .organization = .{
            .names = &.{.{ .value = "Example & Co <SP>" }},
            .display_names = &.{.{ .value = "Example" }},
            .urls = &.{.{ .value = "https://example.org/" }},
        },
        .contacts = &.{
            .{ .contact_type = .technical, .given_name = "Ops", .email_addresses = &.{"mailto:ops@example.org"} },
            .{ .contact_type = .support, .company = "Example", .sur_name = "Desk", .email_addresses = &.{"mailto:help@example.org"}, .telephone_numbers = &.{"+1 555 0100"} },
        },
        .valid_until = "2030-01-01T00:00:00Z",
        .cache_duration = "PT604800S",
    };
}

const authn_request_full_opts: saml.AuthnRequestOptions = .{
    .id = "_req_full_01",
    .issue_instant = "2024-06-01T12:00:00Z",
    .issuer = "https://sp.example.org/metadata",
    .acs_url = "https://sp.example.org/acs/artifact",
    .destination = "https://idp.example.org/sso",
    .name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    .force_authn = true,
    .is_passive = true,
    .protocol_binding = .http_artifact,
    .attribute_consuming_service_index = 1,
    .requested_authn_context = .{
        .comparison = .minimum,
        .class_refs = &.{
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "http://eidas.europa.eu/LoA/substantial",
        },
    },
};

const authn_request_default_opts: saml.AuthnRequestOptions = .{
    .id = "_req_def_01",
    .issue_instant = "2024-06-01T12:00:00Z",
    .issuer = "https://sp.example.org/metadata",
    .acs_url = "https://sp.example.org/acs",
};

// ── byte pins ───────────────────────────────────────────────────────────────

test "SP metadata: minimal document is the pinned, XSD-valid bytes" {
    const out = try saml.buildSpMetadata(testing.allocator, minimal_opts);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(minimal_md_xml, out);
}

test "SP metadata: full document is the pinned, XSD-valid bytes" {
    const out = try saml.buildSpMetadata(testing.allocator, fullOpts());
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(full_md_xml, out);
}

fn signedOpts(sk: *const rsa.SecretKey) saml.SpMetadataOptions {
    var o = fullOpts();
    o.id = "_sp-metadata.1";
    o.sign_with = .{ .rsa = sk };
    return o;
}

test "SP metadata: signed document is the pinned bytes xmlsec1 verified" {
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPem(&sk, ext.sp_priv_pem);
    defer sk.deinit();
    const out = try saml.buildSpMetadata(testing.allocator, signedOpts(&sk));
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(signed_md_xml, out);
}

test "AuthnRequest: default options are the pinned, XSD-valid bytes (unchanged shape)" {
    const out = try saml.buildAuthnRequest(testing.allocator, authn_request_default_opts);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(authn_request_default_xml, out);
}

test "AuthnRequest: every new option is the pinned, XSD-valid bytes" {
    const out = try saml.buildAuthnRequest(testing.allocator, authn_request_full_opts);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(authn_request_full_xml, out);
}

// ── structure, read back through this module's own parser ───────────────────

fn findDeep(el: *const xml.Element, uri: []const u8, local: []const u8) ?*const xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.uri, uri) and std.mem.eql(u8, child.local, local)) return child;
            if (findDeep(child, uri, local)) |f| return f;
        },
        else => {},
    };
    return null;
}

fn countChildren(el: *const xml.Element, uri: []const u8, local: []const u8) usize {
    var n: usize = 0;
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.uri, uri) and std.mem.eql(u8, child.local, local)) n += 1;
        },
        else => {},
    };
    return n;
}

test "SP metadata: parses back with the declared structure and the escaped values intact" {
    const alloc = testing.allocator;
    const out = try saml.buildSpMetadata(alloc, fullOpts());
    defer alloc.free(out);

    var doc = try xml.parse(alloc, out, .{});
    defer doc.deinit();
    const ed = doc.root;
    try testing.expectEqualStrings(saml.md_ns, ed.uri);
    try testing.expectEqualStrings("EntityDescriptor", ed.local);
    try testing.expectEqualStrings("https://sp.example.org/metadata?tenant=a&v=2", ed.attr("", "entityID").?);

    const sp = findDeep(ed, saml.md_ns, "SPSSODescriptor").?;
    try testing.expectEqualStrings(saml.samlp_ns, sp.attr("", "protocolSupportEnumeration").?);
    try testing.expectEqualStrings("true", sp.attr("", "AuthnRequestsSigned").?);
    try testing.expectEqualStrings("true", sp.attr("", "WantAssertionsSigned").?);
    try testing.expectEqual(@as(usize, 2), countChildren(sp, saml.md_ns, "KeyDescriptor"));
    try testing.expectEqual(@as(usize, 2), countChildren(sp, saml.md_ns, "SingleLogoutService"));
    try testing.expectEqual(@as(usize, 2), countChildren(sp, saml.md_ns, "AssertionConsumerService"));
    try testing.expectEqual(@as(usize, 2), countChildren(sp, saml.md_ns, "NameIDFormat"));

    const acs = findDeep(sp, saml.md_ns, "AssertionConsumerService").?;
    try testing.expectEqualStrings(saml.binding_http_post, acs.attr("", "Binding").?);
    try testing.expectEqualStrings("0", acs.attr("", "index").?);
    try testing.expectEqualStrings("true", acs.attr("", "isDefault").?);

    // The KeyDescriptor certificate is exactly the DER we passed.
    const x5c = findDeep(sp, xmldsig.ds_ns, "X509Certificate").?;
    const text = try x5c.textContent(alloc);
    defer alloc.free(text);
    try testing.expectEqualStrings(sp_cert_der_b64, text);

    const org_name = findDeep(ed, saml.md_ns, "OrganizationName").?;
    const on = try org_name.textContent(alloc);
    defer alloc.free(on);
    try testing.expectEqualStrings("Example & Co <SP>", on);

    // SP metadata is not IdP metadata — the parser says so rather than
    // returning an empty IdP.
    try testing.expectError(error.NoIdpDescriptor, saml.parseIdpMetadata(alloc, out));
}

test "SP metadata: the signature verifies through xmldsig and is pinned to the EntityDescriptor" {
    const alloc = testing.allocator;
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPem(&sk, ext.sp_priv_pem);
    defer sk.deinit();
    const out = try saml.buildSpMetadata(alloc, signedOpts(&sk));
    defer alloc.free(out);

    var doc = try xml.parse(alloc, out, .{ .id_attr_names = &.{"ID"} });
    defer doc.deinit();
    // The signature is the FIRST child element (schema: `ds:Signature?` first).
    const first = for (doc.root.children) |c| switch (c.content) {
        .element => |el| break el,
        else => {},
    } else unreachable;
    try testing.expectEqualStrings("Signature", first.local);

    const pk = try rsa.PublicKey.fromPem(sp_pub_pem);
    var res = try xmldsig.verify(alloc, &doc, first, .{ .key = .{ .rsa = pk }, .id_attr = "ID", .max_references = 1 });
    defer res.deinit(alloc);
    try testing.expect(res.valid);
    try testing.expectEqualStrings("#_sp-metadata.1", res.references[0].uri);
    try testing.expect((try doc.findByAttr(alloc, "", "ID", "_sp-metadata.1")).? == doc.root);

    // Tamper with a signed value: the digest no longer matches.
    const tampered = try std.mem.replaceOwned(u8, alloc, out, "https://sp.example.org/acs\"", "https://evil.example/acs\"");
    defer alloc.free(tampered);
    var doc2 = try xml.parse(alloc, tampered, .{ .id_attr_names = &.{"ID"} });
    defer doc2.deinit();
    const sig2 = for (doc2.root.children) |c| switch (c.content) {
        .element => |el| break el,
        else => {},
    } else unreachable;
    var res2 = try xmldsig.verify(alloc, &doc2, sig2, .{ .key = .{ .rsa = pk }, .id_attr = "ID", .max_references = 1 });
    defer res2.deinit(alloc);
    try testing.expect(!res2.valid);
}

test "AuthnRequest: new options parse back; an empty class_refs list omits RequestedAuthnContext" {
    const alloc = testing.allocator;
    const out = try saml.buildAuthnRequest(alloc, authn_request_full_opts);
    defer alloc.free(out);
    var doc = try xml.parse(alloc, out, .{});
    defer doc.deinit();
    const r = doc.root;
    try testing.expectEqualStrings("true", r.attr("", "ForceAuthn").?);
    try testing.expectEqualStrings("true", r.attr("", "IsPassive").?);
    try testing.expectEqualStrings(saml.binding_http_artifact, r.attr("", "ProtocolBinding").?);
    try testing.expectEqualStrings("1", r.attr("", "AttributeConsumingServiceIndex").?);
    const rac = findDeep(r, saml.samlp_ns, "RequestedAuthnContext").?;
    try testing.expectEqualStrings("minimum", rac.attr("", "Comparison").?);
    try testing.expectEqual(@as(usize, 2), countChildren(rac, saml.saml_ns, "AuthnContextClassRef"));

    var o = authn_request_default_opts;
    o.requested_authn_context = .{ .class_refs = &.{} };
    const out2 = try saml.buildAuthnRequest(alloc, o);
    defer alloc.free(out2);
    try testing.expect(std.mem.indexOf(u8, out2, "RequestedAuthnContext") == null);
    try testing.expect(std.mem.indexOf(u8, out2, "ForceAuthn") == null);
    try testing.expect(std.mem.indexOf(u8, out2, "IsPassive") == null);
    try testing.expect(std.mem.indexOf(u8, out2, "AttributeConsumingServiceIndex") == null);

    // u16 upper bound renders as five digits.
    o.attribute_consuming_service_index = 65535;
    const out3 = try saml.buildAuthnRequest(alloc, o);
    defer alloc.free(out3);
    try testing.expect(std.mem.indexOf(u8, out3, "AttributeConsumingServiceIndex=\"65535\"") != null);
}

// ── refusals: each typed, nothing emitted ───────────────────────────────────

test "SP metadata: invalid options are refused with typed errors" {
    const alloc = testing.allocator;
    const acs: []const saml.AcsEndpoint = &.{.{ .location = "https://sp.example.org/acs", .index = 0 }};

    try testing.expectError(error.InvalidEntityId, saml.buildSpMetadata(alloc, .{ .entity_id = "", .assertion_consumer_services = acs }));
    const long = "x" ** 1025;
    try testing.expectError(error.InvalidEntityId, saml.buildSpMetadata(alloc, .{ .entity_id = long, .assertion_consumer_services = acs }));
    // 1024 characters is the limit, counted in characters not octets.
    const ok_long = try saml.buildSpMetadata(alloc, .{ .entity_id = "\u{e9}" ** 1024, .assertion_consumer_services = acs });
    alloc.free(ok_long);

    try testing.expectError(error.NoAssertionConsumerService, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = &.{} }));
    try testing.expectError(error.DuplicateIndex, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = &.{
        .{ .location = "a", .index = 3 },
        .{ .location = "b", .index = 3 },
    } }));
    try testing.expectError(error.MultipleDefaults, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = &.{
        .{ .location = "a", .index = 0, .is_default = true },
        .{ .location = "b", .index = 1, .is_default = true },
    } }));
    try testing.expectError(error.MissingRequiredValue, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = &.{.{ .location = "", .index = 0 }} }));
    try testing.expectError(error.MissingRequiredValue, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .signing_certs_der = &.{""} }));
    try testing.expectError(error.MissingRequiredValue, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .attribute_consuming_services = &.{.{ .index = 0, .service_names = &.{}, .requested_attributes = &.{.{ .name = "a" }} }} }));
    try testing.expectError(error.MissingRequiredValue, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .organization = .{ .names = &.{.{ .value = "n" }}, .display_names = &.{}, .urls = &.{.{ .value = "u" }} } }));
    try testing.expectError(error.DuplicateIndex, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .attribute_consuming_services = &.{
        .{ .index = 1, .service_names = &.{.{ .value = "s" }}, .requested_attributes = &.{.{ .name = "a" }} },
        .{ .index = 1, .service_names = &.{.{ .value = "t" }}, .requested_attributes = &.{.{ .name = "b" }} },
    } }));

    // Signing needs an ID, and the ID must be an ASCII NCName (it is written
    // into the `#id` reference unescaped).
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPem(&sk, ext.sp_priv_pem);
    defer sk.deinit();
    try testing.expectError(error.InvalidId, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .sign_with = .{ .rsa = &sk } }));
    for ([_][]const u8{ "", "1abc", "a\"b", "a b", "#x", "a&b", "\u{e9}" }) |bad| {
        try testing.expectError(error.InvalidId, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .id = bad }));
    }
}

test "SP metadata: characters XML cannot carry are refused, whitespace survives a round trip" {
    const alloc = testing.allocator;
    const acs: []const saml.AcsEndpoint = &.{.{ .location = "https://sp.example.org/acs", .index = 0 }};
    for ([_][]const u8{ "a\x00b", "a\x1bb", "a\xffb", "a\xed\xa0\x80b", "a\u{fffe}b" }) |bad| {
        try testing.expectError(error.InvalidXmlCharacter, saml.buildSpMetadata(alloc, .{ .entity_id = bad, .assertion_consumer_services = acs }));
        try testing.expectError(error.InvalidXmlCharacter, saml.buildSpMetadata(alloc, .{ .entity_id = "e", .assertion_consumer_services = acs, .name_id_formats = &.{bad} }));
    }

    // Tab / LF / CR in an attribute are written as character references, so
    // attribute-value normalization cannot turn them into spaces.
    const out = try saml.buildSpMetadata(alloc, .{ .entity_id = "a\tb\nc\rd", .assertion_consumer_services = acs, .contacts = &.{.{ .contact_type = .other, .company = "x\r\ny" }} });
    defer alloc.free(out);
    var doc = try xml.parse(alloc, out, .{});
    defer doc.deinit();
    try testing.expectEqualStrings("a\tb\nc\rd", doc.root.attr("", "entityID").?);
    const company = findDeep(doc.root, saml.md_ns, "Company").?;
    const ct = try company.textContent(alloc);
    defer alloc.free(ct);
    try testing.expectEqualStrings("x\r\ny", ct);
}

test "SP metadata: no allocation is leaked on any failure path" {
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPem(&sk, ext.sp_priv_pem);
    defer sk.deinit();
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(a: std.mem.Allocator, o: saml.SpMetadataOptions) !void {
            const out = try saml.buildSpMetadata(a, o);
            a.free(out);
        }
    }.run, .{signedOpts(&sk)});
}
