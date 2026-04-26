use crate::core::model::{EvidenceLevel, Finding, RiskAssessmentScope, RiskLevel};

pub struct RiskScoreEngine;

impl RiskScoreEngine {
    /// Partie 3 : tant que le périmètre est DataAndReportOnly, le score reste NON ÉVALUÉ.
    /// Le scoring Vert/Orange/Rouge sera activé quand les collecteurs réels produiront des preuves.
    pub fn evaluate(scope: RiskAssessmentScope, findings: &[Finding]) -> RiskLevel {
        if matches!(
            scope,
            RiskAssessmentScope::FoundationOnly | RiskAssessmentScope::DataAndReportOnly
        ) {
            return RiskLevel::NotAssessed;
        }

        let risk_findings: Vec<&Finding> = findings.iter().filter(|f| f.affects_risk).collect();

        if risk_findings
            .iter()
            .any(|f| f.tags.iter().any(|t| t == "risk:red"))
        {
            return RiskLevel::Red;
        }

        if risk_findings.iter().any(|f| {
            f.tags.iter().any(|t| t == "risk:orange")
                || matches!(f.evidence_level, EvidenceLevel::Strong)
        }) {
            return RiskLevel::Orange;
        }

        if risk_findings.is_empty() {
            RiskLevel::Green
        } else {
            RiskLevel::Orange
        }
    }

    pub fn count_strong(findings: &[Finding]) -> usize {
        findings
            .iter()
            .filter(|f| f.affects_risk && matches!(f.evidence_level, EvidenceLevel::Strong))
            .count()
    }

    pub fn count_weak(findings: &[Finding]) -> usize {
        findings
            .iter()
            .filter(|f| f.affects_risk && matches!(f.evidence_level, EvidenceLevel::Weak))
            .count()
    }

    pub fn count_suspicious(findings: &[Finding]) -> usize {
        findings
            .iter()
            .filter(|f| f.affects_risk && matches!(f.evidence_level, EvidenceLevel::Suspicion))
            .count()
    }
}
