//! Detection tests against known-vulnerable template shapes.

use std::collections::BTreeMap;

use ms_crtd::{
    detect_esc, detect_esc6, parse_enrollment_service_ldap, parse_template_ldap, EscFinding,
};

fn a(k: &str, v: &[u8]) -> (String, Vec<Vec<u8>>) {
    (k.to_string(), vec![v.to_vec()])
}
fn multi(k: &str, vs: &[&[u8]]) -> (String, Vec<Vec<u8>>) {
    (k.to_string(), vs.iter().map(|b| b.to_vec()).collect())
}

/// ESC1 canonical: enrollee supplies subject, Client Authentication EKU,
/// no manager approval, no RA signature.
#[test]
fn esc1_classic() {
    // 0x00010000 = ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"VulnerableUser"),
        a("mspki-cert-template-oid", b"1.3.6.1.4.1.311.21.8.1.1"),
        a("mspki-template-schema-version", b"2"),
        a("mspki-enrollment-flag", b"0"),
        a("mspki-certificate-name-flag", b"65536"),
        a("mspki-private-key-flag", b"16"),
        multi("pkiextendedkeyusage", &[b"1.3.6.1.5.5.7.3.2"]),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    let findings = detect_esc(&t);
    let esc1 = findings
        .iter()
        .find(|f| matches!(f, EscFinding::Esc1 { .. }));
    assert!(esc1.is_some(), "expected ESC1, got {findings:?}");
    if let Some(EscFinding::Esc1 {
        spn_supplied,
        client_auth_eku,
        ..
    }) = esc1
    {
        assert!(*client_auth_eku);
        assert!(*spn_supplied);
    }
}

/// Manager-approval gates neutralise ESC1.
#[test]
fn esc1_suppressed_by_manager_approval() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"NeedsApproval"),
        a("mspki-cert-template-oid", b"1.2.3.4"),
        a("mspki-template-schema-version", b"2"),
        // 0x2 = PEND_ALL_REQUESTS = "CA certificate manager approval"
        a("mspki-enrollment-flag", b"2"),
        a("mspki-certificate-name-flag", b"1"),
        multi("pkiextendedkeyusage", &[b"1.3.6.1.5.5.7.3.2"]),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    let findings = detect_esc(&t);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, EscFinding::Esc1 { .. })),
        "manager-approval template should NOT emit ESC1: {findings:?}"
    );
}

/// ESC3: Certificate-Request-Agent EKU with no gating.
#[test]
fn esc3_enrollment_agent() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"EnrollmentAgent"),
        a("mspki-cert-template-oid", b"1.3.6.1.4.1.311.21.8.1.9"),
        a("mspki-template-schema-version", b"2"),
        a("mspki-enrollment-flag", b"0"),
        a("mspki-certificate-name-flag", b"0"),
        multi("pkiextendedkeyusage", &[b"1.3.6.1.4.1.311.20.2.1"]),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    let findings = detect_esc(&t);
    assert!(
        findings.iter().any(|f| matches!(
            f,
            EscFinding::Esc3 {
                agent_eku: true,
                ..
            }
        )),
        "expected ESC3, got {findings:?}"
    );
}

/// ESC9: NO_SECURITY_EXTENSION bit set.
#[test]
fn esc9_no_security_extension() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"NoSecExt"),
        a("mspki-cert-template-oid", b"1.2.3.4"),
        a("mspki-template-schema-version", b"2"),
        // 0x80000 = NO_SECURITY_EXTENSION
        a("mspki-enrollment-flag", b"524288"),
        a("mspki-certificate-name-flag", b"0"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    let findings = detect_esc(&t);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, EscFinding::Esc9 { .. })),
        "expected ESC9, got {findings:?}"
    );
}

/// ESC15 / EKUwu: schema v1 + enrollee-supplied subject.
#[test]
fn esc15_ekuwu() {
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"V1Template"),
        a("mspki-cert-template-oid", b"1.2.3.4"),
        a("mspki-template-schema-version", b"1"),
        a("mspki-enrollment-flag", b"0"),
        a("mspki-certificate-name-flag", b"1"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    let findings = detect_esc(&t);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, EscFinding::Esc15 { .. })),
        "expected ESC15, got {findings:?}"
    );
}

/// ESC6: CA-side EDITF_ATTRIBUTESUBJECTALTNAME2 + at least one auth template.
#[test]
fn esc6_editf_flag() {
    let ca_attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"CORP-CA"),
        a("dnshostname", b"pki.corp.local"),
        // 0x00040000 = ATTRIBUTE_SUBJECT_ALT_NAME2
        a("flags", b"262144"),
        multi("certificatetemplates", &[b"User", b"WebServer"]),
    ]
    .into_iter()
    .collect();
    let ca = parse_enrollment_service_ldap(&ca_attrs).unwrap();
    assert!(ca.allows_user_supplied_san());

    let t_attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"User"),
        a("mspki-cert-template-oid", b"1.2.3"),
        a("mspki-template-schema-version", b"2"),
        multi("pkiextendedkeyusage", &[b"1.3.6.1.5.5.7.3.2"]),
    ]
    .into_iter()
    .collect();
    let t = parse_template_ldap(&t_attrs).unwrap();

    let finding = detect_esc6(&ca, &[&t]).expect("ESC6 finding");
    match finding {
        EscFinding::Esc6 {
            ca_name,
            user_specified_san_ca,
            template_names,
        } => {
            assert_eq!(ca_name, "CORP-CA");
            assert!(user_specified_san_ca);
            assert_eq!(template_names, vec!["User".to_string()]);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}
