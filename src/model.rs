//! Domain types for parsed ADCS objects.

use crate::flags::{CaEditFlag, EnrollmentFlag, NameFlag, PrivateKeyFlag};
use crate::oid::Oid;

/// A parsed pKICertificateTemplate.
#[derive(Debug, Clone)]
pub struct CertTemplate {
    pub name: String,
    pub oid: Oid,
    /// msPKI-Template-Schema-Version. 1..=4 seen in the wild.
    pub schema_version: i32,
    pub enrollment_flag: EnrollmentFlag,
    pub name_flag: NameFlag,
    pub private_key_flag: PrivateKeyFlag,
    pub ekus: Vec<Oid>,
    /// msPKI-RA-Signature — required enrollment-agent signatures.
    /// `> 0` blocks ESC1/ESC3-abuse (agent must co-sign).
    pub min_ra_signatures: i32,
    /// nTSecurityDescriptor bytes, verbatim. SDDL parsing intentionally
    /// deferred to a companion crate — see README STATUS.
    pub raw_security_descriptor: Option<Vec<u8>>,
}

impl CertTemplate {
    pub fn is_authentication_capable(&self) -> bool {
        use crate::oid::eku;
        self.ekus
            .iter()
            .any(|o| eku::AUTH_EKUS.contains(&o.0.as_str()))
            || self.ekus.is_empty() // no EKU = valid for any usage (subCA-style)
    }

    pub fn requires_manager_approval(&self) -> bool {
        self.enrollment_flag
            .contains(EnrollmentFlag::PEND_ALL_REQUESTS)
    }

    pub fn enrollee_supplies_subject(&self) -> bool {
        self.name_flag.contains(NameFlag::ENROLLEE_SUPPLIES_SUBJECT)
            || self
                .name_flag
                .contains(NameFlag::ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
    }

    pub fn no_security_extension(&self) -> bool {
        self.enrollment_flag
            .contains(EnrollmentFlag::NO_SECURITY_EXTENSION)
    }
}

/// A parsed pKIEnrollmentService (CA) object.
#[derive(Debug, Clone)]
pub struct EnrollmentService {
    pub ca_name: String,
    pub dns_hostname: String,
    /// certificateTemplates values — template `cn`s this CA offers.
    pub templates: Vec<String>,
    /// CA-wide flags; the ESC6-enabling bit is
    /// `CaEditFlag::ATTRIBUTE_SUBJECT_ALT_NAME2`.
    pub edit_flags: CaEditFlag,
}

impl EnrollmentService {
    pub fn allows_user_supplied_san(&self) -> bool {
        self.edit_flags
            .contains(CaEditFlag::ATTRIBUTE_SUBJECT_ALT_NAME2)
    }
}
