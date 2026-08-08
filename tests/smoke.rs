//! Smoke: parse a minimal well-formed template, sanity-check the result.

use std::collections::BTreeMap;

use ms_crtd::{parse_template_ldap, EnrollmentFlag, NameFlag};

fn a(k: &str, v: &[u8]) -> (String, Vec<Vec<u8>>) {
    (k.to_string(), vec![v.to_vec()])
}

#[test]
fn parses_minimal_v2_template() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"WebServer"),
        a("mspki-cert-template-oid", b"1.3.6.1.4.1.311.21.8.1.5"),
        a("mspki-template-schema-version", b"2"),
        a("mspki-enrollment-flag", b"0"),
        a("mspki-certificate-name-flag", b"0"),
        a("mspki-private-key-flag", b"0"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).expect("parse");
    assert_eq!(t.name, "WebServer");
    assert_eq!(t.oid.as_str(), "1.3.6.1.4.1.311.21.8.1.5");
    assert_eq!(t.schema_version, 2);
    assert!(t.enrollment_flag.is_empty());
    assert!(t.name_flag.is_empty());
    assert!(t.ekus.is_empty());
}

#[test]
fn missing_required_attribute_errors() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [a("cn", b"Broken")].into_iter().collect();
    let err = parse_template_ldap(&attrs).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("missing"), "unexpected error: {msg}");
}

#[test]
fn flag_bits_decode() {
    // 0x00080020 = NO_SECURITY_EXTENSION | AUTO_ENROLLMENT
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"T"),
        a("mspki-cert-template-oid", b"1.2.3"),
        a("mspki-template-schema-version", b"2"),
        a("mspki-enrollment-flag", b"524320"),
        a("mspki-certificate-name-flag", b"1"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    assert!(t
        .enrollment_flag
        .contains(EnrollmentFlag::NO_SECURITY_EXTENSION));
    assert!(t.enrollment_flag.contains(EnrollmentFlag::AUTO_ENROLLMENT));
    assert!(t.name_flag.contains(NameFlag::ENROLLEE_SUPPLIES_SUBJECT));
    assert!(t.no_security_extension());
    assert!(t.enrollee_supplies_subject());
}
