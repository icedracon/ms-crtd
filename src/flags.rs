//! bitflags for msPKI-* attributes. Values sourced from
//! [MS-CRTD] and [MS-WCCE] public docs. Only the flags relevant
//! to ESC1-ESC15 detection are named explicitly; the rest survive
//! via `bits()` for consumers that want the raw u32.

use bitflags::bitflags;

bitflags! {
    /// msPKI-Certificate-Name-Flag — how the subject/SAN is populated.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NameFlag: u32 {
        const ENROLLEE_SUPPLIES_SUBJECT           = 0x0000_0001;
        const OLD_CERT_SUPPLIES_SUBJECT_AND_ALT   = 0x0000_0008;
        const ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME  = 0x0001_0000;
        const SUBJECT_ALT_REQUIRE_DOMAIN_DNS      = 0x0040_0000;
        const SUBJECT_ALT_REQUIRE_SPN             = 0x0080_0000;
        const SUBJECT_ALT_REQUIRE_DIRECTORY_GUID  = 0x0100_0000;
        const SUBJECT_ALT_REQUIRE_UPN             = 0x0200_0000;
        const SUBJECT_ALT_REQUIRE_EMAIL           = 0x0400_0000;
        const SUBJECT_ALT_REQUIRE_DNS             = 0x0800_0000;
        const SUBJECT_REQUIRE_DNS_AS_CN           = 0x1000_0000;
        const SUBJECT_REQUIRE_EMAIL               = 0x2000_0000;
        const SUBJECT_REQUIRE_COMMON_NAME         = 0x4000_0000;
        const SUBJECT_REQUIRE_DIRECTORY_PATH      = 0x8000_0000;
    }
}

bitflags! {
    /// msPKI-Enrollment-Flag — enrollment-time behaviors.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EnrollmentFlag: u32 {
        const INCLUDE_SYMMETRIC_ALGORITHMS         = 0x0000_0001;
        const PEND_ALL_REQUESTS                    = 0x0000_0002; // "CA certificate manager approval"
        const PUBLISH_TO_KRA_CONTAINER             = 0x0000_0004;
        const PUBLISH_TO_DS                        = 0x0000_0008;
        const AUTO_ENROLLMENT_CHECK_USER_DS_CERT   = 0x0000_0010;
        const AUTO_ENROLLMENT                      = 0x0000_0020;
        const PREVIOUS_APPROVAL_VALIDATE_REENROLL  = 0x0000_0040;
        const USER_INTERACTION_REQUIRED            = 0x0000_0100;
        const REMOVE_INVALID_CERTIFICATES          = 0x0000_0400;
        const ALLOW_ENROLL_ON_BEHALF_OF            = 0x0000_0800;
        const INCLUDE_OCSP_REVOCATION_NOCHECK      = 0x0000_1000;
        const REUSE_KEY_ON_FULL_SMARTCARD          = 0x0000_2000;
        const NO_REVOCATION_INFO_IN_ISSUED_CERTS   = 0x0000_4000;
        const INCLUDE_BASIC_CONSTRAINTS_FOR_EE     = 0x0000_8000;
        const IGNORE_ENROLL_ON_REENROLL            = 0x0001_0000;
        const ISSUANCE_POLICIES_FROM_REQUEST       = 0x0002_0000;
        const SKIP_AUTO_RENEWAL                    = 0x0004_0000;
        const NO_SECURITY_EXTENSION                = 0x0008_0000; // ESC9
    }
}

bitflags! {
    /// msPKI-Private-Key-Flag — key-material handling.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivateKeyFlag: u32 {
        const REQUIRE_PRIVATE_KEY_ARCHIVAL          = 0x0000_0001;
        const EXPORTABLE_KEY                        = 0x0000_0010;
        const STRONG_KEY_PROTECTION_REQUIRED        = 0x0000_0020;
        const REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x0000_0040;
        const REQUIRE_SAME_KEY_RENEWAL              = 0x0000_0080;
        const USE_LEGACY_PROVIDER                   = 0x0000_0100;
        const ATTEST_NONE                           = 0x0000_0000;
        const ATTEST_REQUIRED                       = 0x0000_2000;
        const ATTEST_PREFERRED                      = 0x0000_1000;
        const ATTESTATION_WITHOUT_POLICY            = 0x0000_4000;
        const EK_TRUST_ON_USE                       = 0x0020_0000;
        const EK_VALIDATE_CERT                      = 0x0040_0000;
        const EK_VALIDATE_KEY                       = 0x0080_0000;
        const HELLO_LOGON_KEY                       = 0x0020_0000; // (aliased in docs)
    }
}

bitflags! {
    /// mspki-enrollment-service Flags on the pKIEnrollmentService object.
    /// Not to be confused with template EnrollmentFlag above.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CaEditFlag: u32 {
        /// EDITF_ATTRIBUTESUBJECTALTNAME2 — CA-wide "trust the SAN in the CSR".
        /// When set, ANY template becomes ESC6-abusable.
        const ATTRIBUTE_SUBJECT_ALT_NAME2 = 0x0004_0000;
    }
}
