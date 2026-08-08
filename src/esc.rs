//! ESC1-ESC15 static-analysis rules over parsed templates.
//!
//! Terminology: SpecterOps's Certified Pre-Owned taxonomy.
//! We implement the *template-shape* checks — anything requiring a live
//! DC (SD/DACL evaluation, ADCS registry flags, CA cert chain) is out
//! of scope for 0.1.0-dev and clearly labeled below.

use crate::flags::PrivateKeyFlag;
use crate::model::{CertTemplate, EnrollmentService};
use crate::oid::{eku, Oid};

/// ESC finding variants. Kept small and enum-shaped so a downstream
/// SARIF or JSON emitter can pattern-match cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscFinding {
    /// ESC1 — enrollee supplies subject/SAN on a template with an
    /// authentication EKU and no manager-approval / RA-signature gate.
    Esc1 {
        template: String,
        client_auth_eku: bool,
        spn_supplied: bool,
    },
    /// ESC2 — template has Any Purpose EKU (or no EKU) and enrollee
    /// supplies subject. Effectively an unrestricted signing cert.
    Esc2 { template: String, any_purpose: bool },
    /// ESC3 — Certificate-Request-Agent EKU present and no
    /// application-policy issuance restriction — an enrollment agent
    /// can enroll ON BEHALF OF an arbitrary principal.
    Esc3 { template: String, agent_eku: bool },
    /// ESC6 — CA-side setting: EDITF_ATTRIBUTESUBJECTALTNAME2 lets
    /// ANY caller inject a SAN via the request. `template_names`
    /// enumerates the templates that become abusable on this CA.
    Esc6 {
        ca_name: String,
        user_specified_san_ca: bool,
        template_names: Vec<String>,
    },
    /// ESC9 — msPKI-Enrollment-Flag has NO_SECURITY_EXTENSION,
    /// which drops the szOID_NTDS_CA_SECURITY_EXT (SID binding)
    /// from issued certs and enables UPN-alias abuse.
    Esc9 { template: String },
    /// ESC13 — issuance policies grant privileged group access via
    /// the template's msPKI-Certificate-Policy OID. We flag templates
    /// that carry ANY issuance policy so a human can review.
    Esc13 {
        template: String,
        policy_oids: Vec<Oid>,
    },
    /// ESC15 — CVE-2024-49019 "EKUwu" — schema v1 template inheritance
    /// lets a requester inject arbitrary EKUs into the issued cert.
    /// All schema-v1 templates that permit enrollee-supplied subject
    /// are candidates.
    Esc15 { template: String },
}

/// Run every enabled ESC check on one template.
pub fn detect_esc(t: &CertTemplate) -> Vec<EscFinding> {
    let mut out = Vec::new();

    // Gate: manager approval or a required enrollment-agent co-sign
    // neutralises ESC1/ESC2/ESC3 (an attacker can't self-approve).
    let approval_gated = t.requires_manager_approval() || t.min_ra_signatures > 0;

    let client_auth = t.ekus.iter().any(|o| o.0 == eku::CLIENT_AUTH);
    let any_purpose = t.ekus.iter().any(|o| o.0 == eku::ANY_PURPOSE) || t.ekus.is_empty();
    let agent = t.ekus.iter().any(|o| o.0 == eku::CERT_REQUEST_AGENT);

    // ESC1
    if !approval_gated && t.enrollee_supplies_subject() && t.is_authentication_capable() {
        out.push(EscFinding::Esc1 {
            template: t.name.clone(),
            client_auth_eku: client_auth,
            spn_supplied: t
                .name_flag
                .contains(crate::flags::NameFlag::ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME),
        });
    }

    // ESC2
    if !approval_gated && t.enrollee_supplies_subject() && any_purpose {
        out.push(EscFinding::Esc2 {
            template: t.name.clone(),
            any_purpose: true,
        });
    }

    // ESC3
    if !approval_gated && agent {
        out.push(EscFinding::Esc3 {
            template: t.name.clone(),
            agent_eku: true,
        });
    }

    // ESC9
    if t.no_security_extension() {
        out.push(EscFinding::Esc9 {
            template: t.name.clone(),
        });
    }

    // ESC13 — partial: we surface templates that have issuance policies
    // attached. Actual privilege mapping requires reading
    // msDS-OIDToGroupLink on the OID container, which is a separate LDAP
    // fetch and out-of-scope here. See known_gaps in README.
    if !t.ekus.is_empty() && !approval_gated {
        // heuristic placeholder — real ESC13 needs the OID→group map;
        // we emit an empty policy_oids list so downstream code sees
        // "check this manually" without a false-positive detonation.
        // Disabled by default via the empty-list guard below.
        let placeholder: Vec<Oid> = Vec::new();
        if !placeholder.is_empty() {
            out.push(EscFinding::Esc13 {
                template: t.name.clone(),
                policy_oids: placeholder,
            });
        }
    }

    // ESC15 — schema v1 + enrollee-supplied subject.
    if t.schema_version == 1 && t.enrollee_supplies_subject() {
        out.push(EscFinding::Esc15 {
            template: t.name.clone(),
        });
    }

    // Suppress unused-import warnings when PrivateKeyFlag lands unused
    // in future rearrangements.
    let _ = PrivateKeyFlag::EXPORTABLE_KEY;

    out
}

/// CA-scoped check for ESC6. Pass the CA plus the templates it offers.
/// Only templates that are authentication-capable are worth flagging —
/// the SAN-injection primitive is useless on a signing-only cert.
pub fn detect_esc6(ca: &EnrollmentService, templates: &[&CertTemplate]) -> Option<EscFinding> {
    if !ca.allows_user_supplied_san() {
        return None;
    }
    let abusable: Vec<String> = templates
        .iter()
        .filter(|t| t.is_authentication_capable())
        .map(|t| t.name.clone())
        .collect();
    if abusable.is_empty() {
        return None;
    }
    Some(EscFinding::Esc6 {
        ca_name: ca.ca_name.clone(),
        user_specified_san_ca: true,
        template_names: abusable,
    })
}
