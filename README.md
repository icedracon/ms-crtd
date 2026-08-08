# ms-crtd

AD-CS certificate template parser and ESC1-ESC15 static-analysis rules.

**STATUS: 0.1.0-dev (pre-alpha).** Skeleton with partial implementation.
Not yet publishable. API is unstable.

## What it does

Given the LDAP attributes of a `pKICertificateTemplate` or
`pKIEnrollmentService` object (which you fetch yourself — this crate does
no network I/O), decode them into typed Rust and run the Certified
Pre-Owned ESC1-ESC15 template-shape checks.

## Minimal usage

```rust
use std::collections::BTreeMap;
use ms_crtd::{parse_template_ldap, detect_esc};

let mut attrs: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
attrs.insert("cn".into(), vec![b"User".to_vec()]);
attrs.insert("mspki-cert-template-oid".into(),
             vec![b"1.3.6.1.4.1.311.21.8.1.2".to_vec()]);
attrs.insert("mspki-template-schema-version".into(), vec![b"2".to_vec()]);
attrs.insert("mspki-certificate-name-flag".into(), vec![b"65536".to_vec()]);
attrs.insert("pkiextendedkeyusage".into(),
             vec![b"1.3.6.1.5.5.7.3.2".to_vec()]);

let t = parse_template_ldap(&attrs).unwrap();
let findings = detect_esc(&t);
```

Attribute keys are looked up case-insensitively; keep them lowercase for
best performance.

## What's implemented

- Full flag decoding for `msPKI-Certificate-Name-Flag`,
  `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, plus CA-side `flags`.
- EKU / application-policy OID lists (ASCII and UTF-16LE payloads).
- Detection rules: **ESC1, ESC2, ESC3, ESC6, ESC9, ESC15**.
- Manager-approval / RA-signature gating (suppresses false positives).

## What's stubbed or deferred

- **`raw_security_descriptor`** — exposed as bytes; no SDDL/DACL decode.
  Consumer must run this through a separate parser to enumerate which
  principals can enroll. This is intentional; it is not a `todo!()` panic.
- **ESC13** — the variant exists but is only emitted when
  `msDS-OIDToGroupLink` mapping is provided (not yet accepted by any API).
  Waiting on a live-DC iteration to model the mapping cleanly.
- **ESC4, ESC5, ESC7, ESC8, ESC10, ESC11, ESC12, ESC14** — not implemented.
  Most require CA-level or forest-level context, not template shape alone.
- ADSI signed-int quirks beyond the common cases are unverified against
  real Windows Server 2016/2019/2022 output.

## Deps

`bitflags`, `thiserror`, `hex`. No `serde`, no `serde_json`, no runtime.

## License

MIT.
