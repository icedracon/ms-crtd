//! ms-crtd — AD-CS certificate template parser and ESC1-ESC15 static analyser.
//!
//! # Scope
//!
//! Parses the LDAP attributes of `pKICertificateTemplate` and
//! `pKIEnrollmentService` objects (as read by the caller) into typed Rust
//! values, then runs template-shape checks corresponding to the
//! Certified Pre-Owned ESC taxonomy.
//!
//! This crate performs NO network I/O — consumers pass the raw attribute
//! byte lists in via `parse_template_ldap` / `parse_enrollment_service_ldap`.
//!
//! # Status: 0.1.0-dev (pre-alpha)
//!
//! - ESC1, ESC2, ESC3, ESC6, ESC9, ESC15: implemented against template shape.
//! - ESC13: partial — flag emitted only when the OID→group map is provided
//!   by the caller (which we don't yet accept). See `known_gaps` in README.
//! - Security-descriptor DACL parsing: deferred. `raw_security_descriptor`
//!   is exposed as bytes.
//!
//! # Example
//!
//! ```ignore
//! use std::collections::BTreeMap;
//! use ms_crtd::{parse_template_ldap, detect_esc};
//!
//! let mut attrs: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
//! attrs.insert("cn".into(), vec![b"User".to_vec()]);
//! attrs.insert("mspki-cert-template-oid".into(),
//!              vec![b"1.3.6.1.4.1.311.21.8.1.2".to_vec()]);
//! attrs.insert("mspki-template-schema-version".into(), vec![b"2".to_vec()]);
//! let t = parse_template_ldap(&attrs).unwrap();
//! let findings = detect_esc(&t);
//! ```

pub mod error;
pub mod esc;
pub mod flags;
pub mod model;
pub mod oid;
pub mod parse;

pub use error::{Error, Result};
pub use esc::{detect_esc, detect_esc6, EscFinding};
pub use flags::{CaEditFlag, EnrollmentFlag, NameFlag, PrivateKeyFlag};
pub use model::{CertTemplate, EnrollmentService};
pub use oid::Oid;
pub use parse::{parse_enrollment_service_ldap, parse_template_ldap, Attrs};
