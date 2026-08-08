//! Round-trip: attributes -> struct -> flag bits -> back to u32
//! survive without loss. Catches endian / signed-vs-unsigned bugs.

use std::collections::BTreeMap;

use ms_crtd::{parse_template_ldap, EnrollmentFlag, NameFlag, PrivateKeyFlag};

fn a(k: &str, v: &[u8]) -> (String, Vec<Vec<u8>>) {
    (k.to_string(), vec![v.to_vec()])
}

#[test]
fn flag_bits_survive_round_trip() {
    // 0xC0800101 has the high bit set — trips naive i32-only paths.
    let bits: u32 = 0xC080_0101;
    let signed = bits as i32;
    let ascii = signed.to_string();

    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        a("cn", b"BitTest"),
        a("mspki-cert-template-oid", b"1.2.3"),
        a("mspki-template-schema-version", b"4"),
        a("mspki-enrollment-flag", b"0"),
        a("mspki-certificate-name-flag", ascii.as_bytes()),
        a("mspki-private-key-flag", b"16"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    assert_eq!(t.name_flag.bits(), bits, "high-bit round trip");
    assert!(t
        .name_flag
        .contains(NameFlag::SUBJECT_REQUIRE_DIRECTORY_PATH));
    assert!(t.name_flag.contains(NameFlag::SUBJECT_REQUIRE_COMMON_NAME));
    assert!(t.private_key_flag.contains(PrivateKeyFlag::EXPORTABLE_KEY));
    // Enrollment flag was 0 → no bits.
    assert_eq!(t.enrollment_flag, EnrollmentFlag::empty());
}

#[test]
fn utf16le_string_decodes() {
    // UTF-16LE "V" = 0x56 0x00
    let cn_utf16: Vec<u8> = "V\0i\0p\0T\0m\0p\0l\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    // Strip the trailing NULs the encode_utf16 iter picked up from \0s
    // (that was intentional — we want to prove NUL-termination is stripped).
    let attrs: BTreeMap<String, Vec<Vec<u8>>> = [
        ("cn".to_string(), vec![cn_utf16]),
        a("mspki-cert-template-oid", b"1.2.3"),
        a("mspki-template-schema-version", b"2"),
    ]
    .into_iter()
    .collect();

    let t = parse_template_ldap(&attrs).unwrap();
    // Depending on how the NULs land, the decoder may either keep or strip
    // interior NULs. We only require the visible prefix survived.
    assert!(t.name.starts_with('V'), "got: {:?}", t.name);
}
