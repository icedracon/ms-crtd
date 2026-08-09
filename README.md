# ms-crtd

[![Crates.io](https://img.shields.io/crates/v/ms-crtd.svg)](https://crates.io/crates/ms-crtd)
[![Docs.rs](https://docs.rs/ms-crtd/badge.svg)](https://docs.rs/ms-crtd)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AD CS certificate-template parser and Certified Pre-Owned **ESC1-ESC15** static-analysis engine, in Rust. For red teamers, detection engineers, and AD auditors who need to reason about `pKICertificateTemplate` objects without shelling out to `certipy find` or PowerShell.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Part of the [icedracon Rust offensive AD ecosystem](https://github.com/icedracon).

## What it does

Feed the crate the raw LDAP attributes of a `pKICertificateTemplate` (or `pKIEnrollmentService`) object — which you fetch yourself; ms-crtd does zero network I/O — and it decodes them into typed Rust (`CertTemplate`), including full flag decoding for `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, and CA-side `flags`, plus ASCII- and UTF-16LE-encoded EKU / application-policy OID lists. It then runs the SpecterOps [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) ESC1-ESC15 template-shape checks and returns a `Vec<EscFinding>` you can hand to an enrollment client such as [`ms-icpr`](https://github.com/icedracon/ms-icpr).

## Usage

```rust
use std::collections::BTreeMap;
use ms_crtd::{parse_template_ldap, detect_esc};

let mut attrs: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
attrs.insert("cn".into(), vec![b"User".to_vec()]);
attrs.insert("mspki-cert-template-oid".into(),
             vec![b"1.3.6.1.4.1.311.21.8.1.2".to_vec()]);
attrs.insert("mspki-template-schema-version".into(), vec![b"2".to_vec()]);
// ENROLLEE_SUPPLIES_SUBJECT -> textbook ESC1
attrs.insert("mspki-certificate-name-flag".into(), vec![b"65536".to_vec()]);
attrs.insert("pkiextendedkeyusage".into(),
             vec![b"1.3.6.1.5.5.7.3.2".to_vec()]);

let t = parse_template_ldap(&attrs).unwrap();
for f in detect_esc(&t) {
    println!("{:?} on {}: {}", f.code, t.cn, f.reason);
}
```

Attribute keys are looked up case-insensitively; keep them lowercase for best performance.

## What works / what does not (this version)

- Working:
  - Full flag decoding for `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, CA-side `flags`
  - EKU / application-policy OID lists (ASCII and UTF-16LE payloads)
  - ESC1, ESC2, ESC3, ESC6, ESC9, ESC15 detection
  - Manager-approval and RA-signature gating (suppresses obvious FPs)
  - `raw_security_descriptor` surfaced as bytes for a downstream SDDL/DACL parser
- Stubbed / deferred:
  - ESC13 variant exists but only fires when a caller supplies an `msDS-OIDToGroupLink` mapping (no API accepts it yet)
  - ESC4, ESC5, ESC7, ESC8, ESC10, ESC11, ESC12, ESC14 — most require CA-level or forest-level context, not template shape alone
  - ADSI signed-int quirks beyond the common cases are unverified against real Server 2016/2019/2022 output

## Related icedracon crates

Part of a 4-crate ADCS attack chain — template parsing all the way to a live PKINIT-derived TGT:

- **ms-crtd** (this crate) — parse `pKICertificateTemplate` LDAP attrs, emit ESC findings
- [`ms-icpr`](https://github.com/icedracon/ms-icpr) — submit ESC1 CSRs to the CA over MS-ICPR / MS-WCCE
- [`ms-pkca`](https://github.com/icedracon/ms-pkca) — PKINIT the issued cert into a Kerberos TGT + UnPAC-the-hash
- [`ms-kile-fast`](https://github.com/icedracon/ms-kile-fast) — RFC 6113 FAST armor for the AS-REQ / TGS-REQ

Together they aim for [Certipy](https://github.com/ly4k/Certipy) parity in pure Rust with an S-tier dep tree.

## Dependencies

`bitflags`, `thiserror`, `hex`. No `serde`, no `serde_json`, no async runtime.

## License

MIT (C) 2026 [zevs](https://github.com/icedracon)
