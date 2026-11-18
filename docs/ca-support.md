# CA Support

Certower talks to CAs through the generic ACME issuer. The presets in
[`internal/capresets`](../internal/capresets) only carry the directory URL,
whether External Account Binding (EAB) is required, and a docs link.

Status as of 2026-11. Verify endpoints with your CA before relying on them.

| CA | ACME | EAB | Notes |
|----|------|-----|-------|
| Let's Encrypt | Yes | No | Free, DV only. |
| ZeroSSL | Yes | Yes (auto-generated) | Free DV tier. |
| Google Trust Services | Yes | Yes | Free, EAB keys from Google Cloud. |
| Sectigo | Yes | Yes | DV/OV via ACME subscriptions from resellers or SCM. |
| GlobalSign (Atlas) | Yes | Yes | |
| DigiCert | Yes | Yes | The legacy CertCentral ACME endpoint and EAB were retired on 2026-02-24. Use the new endpoint from your DigiCert account. |
| TWCA (臺灣網路認證) | Yes | Ask the CA | Supports ACME and the MSSL 2.0 program. Get the endpoint and EAB from TWCA. |
| Chunghwa Telecom (中華電信) | Announced | Unknown | Chrome 139+ distrusts TLS certificates from ePKI Root CA and HiPKI Root CA - G1 issued after 2025-07-31. CHT has applied for re-inclusion. No public ACME endpoint was found. |

CAs without ACME can be used with the manual issuer: Certower generates the key
and CSR, a person submits the CSR to the CA, and the uploaded certificate is
deployed automatically.
