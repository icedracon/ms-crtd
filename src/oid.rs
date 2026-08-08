//! Minimal OID handling. We do NOT implement full X.690 encoding here —
//! most ADCS attributes carry OIDs as UTF-16LE dotted-decimal strings
//! (e.g. "1.3.6.1.5.5.7.3.2"), which is what we parse.

use std::fmt;

/// Dotted-decimal OID. Owned. Cheap to clone for the arity we deal with.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub String);

impl Oid {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Oid(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Oid {
    fn from(s: &str) -> Self {
        Oid(s.to_string())
    }
}

/// Well-known EKUs relevant to ESC detection.
pub mod eku {
    pub const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    pub const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    pub const PKINIT_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";
    pub const SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
    pub const ANY_PURPOSE: &str = "2.5.29.37.0";
    pub const CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1"; // "Enrollment Agent"

    /// EKUs that permit domain authentication (Kerberos PKINIT / Schannel client).
    /// Presence of ANY of these on a template = authentication-capable.
    pub const AUTH_EKUS: &[&str] = &[
        CLIENT_AUTH,
        PKINIT_CLIENT_AUTH,
        SMARTCARD_LOGON,
        ANY_PURPOSE,
    ];
}

/// Best-effort parser for ADCS OID-list byte payload.
///
/// Real ADCS `pKIExtendedKeyUsage` is a multi-valued attribute where each value
/// is a separately-returned OID string. But some LDAP client stacks concatenate
/// them with NULs or ship the raw UTF-16LE. This helper is deliberately liberal:
/// if the bytes are ASCII-digit-and-dot, return as-is; if they look like
/// UTF-16LE, decode; otherwise, return None.
pub fn parse_oid_value(bytes: &[u8]) -> Option<Oid> {
    if bytes.is_empty() {
        return None;
    }
    // Fast path: pure ASCII dotted-decimal.
    if bytes.iter().all(|b| b.is_ascii_digit() || *b == b'.') {
        return std::str::from_utf8(bytes).ok().map(Oid::new);
    }
    // UTF-16LE (Windows LDAP frequently returns strings this way when raw).
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let mut u16s = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        if let Ok(s) = String::from_utf16(&u16s) {
            let trimmed = s.trim_end_matches('\0');
            if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') && !trimmed.is_empty() {
                return Some(Oid::new(trimmed));
            }
        }
    }
    None
}
