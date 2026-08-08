//! LDAP-attribute -> Rust-struct decoding for pKICertificateTemplate
//! and pKIEnrollmentService objects.
//!
//! Consumers read attributes off the wire however they like (ldap3, windows-ldap,
//! raw ADSI, canned test fixtures) and hand us a `BTreeMap<String, Vec<Vec<u8>>>`
//! keyed by attribute name (case-insensitive canonicalized to lowercase).

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::flags::{CaEditFlag, EnrollmentFlag, NameFlag, PrivateKeyFlag};
use crate::model::{CertTemplate, EnrollmentService};
use crate::oid::{parse_oid_value, Oid};

pub type Attrs = BTreeMap<String, Vec<Vec<u8>>>;

/// Decode a Windows-style LDAP string. Accepts UTF-8, or UTF-16LE with an
/// optional trailing NUL. Returns `None` for empty input.
pub(crate) fn decode_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    // Try UTF-8 first.
    if let Ok(s) = std::str::from_utf8(bytes) {
        let t = s.trim_end_matches('\0');
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    // Fall back to UTF-16LE (Windows LDAP native encoding).
    if bytes.len() % 2 == 0 {
        let mut u16s = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        if let Ok(s) = String::from_utf16(&u16s) {
            let t = s.trim_end_matches('\0');
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Decode a 32-bit signed integer attribute. AD sends these as ASCII decimal.
pub(crate) fn decode_int_i32(name: &'static str, bytes: &[u8]) -> Result<i32> {
    let s = decode_string(bytes).ok_or(Error::BadInteger {
        name,
        byte_len: bytes.len(),
    })?;
    s.trim().parse::<i32>().map_err(|_| Error::BadInteger {
        name,
        byte_len: bytes.len(),
    })
}

/// Same as above but keep the raw u32 bit-pattern (flags are u32 in the docs
/// but ADSI serializes signed).
pub(crate) fn decode_flags_u32(name: &'static str, bytes: &[u8]) -> Result<u32> {
    decode_int_i32(name, bytes).map(|v| v as u32)
}

fn get<'a>(attrs: &'a Attrs, key: &str) -> Option<&'a Vec<Vec<u8>>> {
    // canonicalize lookup to lowercase; caller is expected to have stored
    // keys in lowercase already, but be forgiving.
    attrs
        .get(key)
        .or_else(|| attrs.get(&key.to_ascii_lowercase()))
}

fn one<'a>(attrs: &'a Attrs, key: &'static str) -> Result<&'a [u8]> {
    let v = get(attrs, key).ok_or(Error::MissingAttribute(key))?;
    let first = v.first().ok_or(Error::EmptyAttribute(key))?;
    Ok(first.as_slice())
}

fn one_opt<'a>(attrs: &'a Attrs, key: &str) -> Option<&'a [u8]> {
    get(attrs, key).and_then(|v| v.first().map(|x| x.as_slice()))
}

/// Parse a pKICertificateTemplate attribute set.
///
/// Required: cn, msPKI-Cert-Template-OID, msPKI-Template-Schema-Version.
/// Missing flags default to zero (a valid AD template state — means "no flags set").
pub fn parse_template_ldap(attrs: &Attrs) -> Result<CertTemplate> {
    let name = decode_string(one(attrs, "cn")?).ok_or(Error::BadString { name: "cn" })?;

    let oid_bytes = one(attrs, "mspki-cert-template-oid")?;
    let oid = decode_string(oid_bytes)
        .map(Oid::new)
        .ok_or(Error::BadString {
            name: "msPKI-Cert-Template-OID",
        })?;

    let schema_version = decode_int_i32(
        "msPKI-Template-Schema-Version",
        one(attrs, "mspki-template-schema-version")?,
    )?;

    let enrollment_flag = one_opt(attrs, "mspki-enrollment-flag")
        .map(|b| decode_flags_u32("msPKI-Enrollment-Flag", b))
        .transpose()?
        .map(EnrollmentFlag::from_bits_retain)
        .unwrap_or(EnrollmentFlag::empty());

    let name_flag = one_opt(attrs, "mspki-certificate-name-flag")
        .map(|b| decode_flags_u32("msPKI-Certificate-Name-Flag", b))
        .transpose()?
        .map(NameFlag::from_bits_retain)
        .unwrap_or(NameFlag::empty());

    let private_key_flag = one_opt(attrs, "mspki-private-key-flag")
        .map(|b| decode_flags_u32("msPKI-Private-Key-Flag", b))
        .transpose()?
        .map(PrivateKeyFlag::from_bits_retain)
        .unwrap_or(PrivateKeyFlag::empty());

    // pKIExtendedKeyUsage — multi-valued OID list.
    let ekus = get(attrs, "pkiextendedkeyusage")
        .map(|vals| vals.iter().filter_map(|b| parse_oid_value(b)).collect())
        .unwrap_or_default();

    // msPKI-Certificate-Application-Policy is the modern equivalent of EKUs
    // for schema v2+; if present, merge in.
    let mut merged_ekus: Vec<Oid> = ekus;
    if let Some(vals) = get(attrs, "mspki-certificate-application-policy") {
        for b in vals {
            if let Some(o) = parse_oid_value(b) {
                if !merged_ekus.contains(&o) {
                    merged_ekus.push(o);
                }
            }
        }
    }

    let min_ra_signatures = one_opt(attrs, "mspki-ra-signature")
        .map(|b| decode_int_i32("msPKI-RA-Signature", b))
        .transpose()?
        .unwrap_or(0);

    // Read the DACL bytes verbatim. Full SDDL parse is out of scope for
    // 0.1.0-dev — consumers who need it can pipe raw_security_descriptor
    // through a proper SDDL decoder. This is the pragmatic placeholder,
    // NOT a todo!() panic.
    let raw_security_descriptor = one_opt(attrs, "ntsecuritydescriptor").map(|b| b.to_vec());

    Ok(CertTemplate {
        name,
        oid,
        schema_version,
        enrollment_flag,
        name_flag,
        private_key_flag,
        ekus: merged_ekus,
        min_ra_signatures,
        raw_security_descriptor,
    })
}

/// Parse a pKIEnrollmentService (CA) object.
pub fn parse_enrollment_service_ldap(attrs: &Attrs) -> Result<EnrollmentService> {
    let ca_name = decode_string(one(attrs, "cn")?).ok_or(Error::BadString { name: "cn" })?;
    let dns_hostname = decode_string(one(attrs, "dnshostname")?).ok_or(Error::BadString {
        name: "dnsHostName",
    })?;

    let templates = get(attrs, "certificatetemplates")
        .map(|vals| vals.iter().filter_map(|b| decode_string(b)).collect())
        .unwrap_or_default();

    let edit_flags = one_opt(attrs, "flags")
        .map(|b| decode_flags_u32("flags", b))
        .transpose()?
        .map(CaEditFlag::from_bits_retain)
        .unwrap_or(CaEditFlag::empty());

    Ok(EnrollmentService {
        ca_name,
        dns_hostname,
        templates,
        edit_flags,
    })
}
