use crate::core::model::{EvidenceLevel, Finding, RiskAssessmentScope, RiskLevel};

pub struct RiskScoreEngine;

impl RiskScoreEngine {
    pub fn evaluate(scope: RiskAssessmentScope, findings: &[Finding]) -> RiskLevel {
        if scope == RiskAssessmentScope::ArchitectureOnly {
            return RiskLevel::NotAssessed;
        }

        let risk_findings: Vec<&Finding> = findings.iter().filter(|f| f.affects_risk).collect();

        if risk_findings
            .iter()
            .any(|f| f.tags.iter().any(|t| t == "risk:red"))
        {
            return RiskLevel::Red;
        }

        if risk_findings
            .iter()
            .any(|f| f.tags.iter().any(|t| t == "risk:orange"))
        {
            return RiskLevel::Orange;
        }

        if risk_findings
            .iter()
            .any(|f| matches!(f.evidence_level, EvidenceLevel::Strong))
        {
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

#[cfg(test)]
mod tests {
    use super::RiskScoreEngine;
    use crate::core::model::{
        EvidenceLevel, Finding, FindingCategory, RiskAssessmentScope, RiskLevel,
    };

    fn risk_finding(evidence_level: EvidenceLevel, tags: Vec<String>) -> Finding {
        Finding::risk_finding(
            "TEST-001",
            FindingCategory::Process,
            "Constat test",
            "Description test",
            evidence_level,
            "test",
            Vec::new(),
            tags,
            90,
            None,
        )
    }

    #[test]
    fn architecture_only_scope_is_never_scored() {
        let findings = vec![risk_finding(
            EvidenceLevel::Strong,
            vec!["risk:red".to_string()],
        )];

        assert_eq!(
            RiskScoreEngine::evaluate(RiskAssessmentScope::ArchitectureOnly, &findings),
            RiskLevel::NotAssessed
        );
    }

    #[test]
    fn audit_scope_without_risk_findings_is_green() {
        assert_eq!(
            RiskScoreEngine::evaluate(RiskAssessmentScope::AuditEvidence, &[]),
            RiskLevel::Green
        );
    }

    #[test]
    fn explicit_risk_tags_take_priority() {
        let red = vec![risk_finding(
            EvidenceLevel::Suspicion,
            vec!["risk:red".to_string()],
        )];
        let orange = vec![risk_finding(
            EvidenceLevel::Suspicion,
            vec!["risk:orange".to_string()],
        )];

        assert_eq!(
            RiskScoreEngine::evaluate(RiskAssessmentScope::AuditEvidence, &red),
            RiskLevel::Red
        );
        assert_eq!(
            RiskScoreEngine::evaluate(RiskAssessmentScope::AuditEvidence, &orange),
            RiskLevel::Orange
        );
    }

    #[test]
    fn evidence_counters_only_count_risk_affecting_findings() {
        let mut ignored = risk_finding(EvidenceLevel::Strong, Vec::new());
        ignored.affects_risk = false;
        let findings = vec![
            ignored,
            risk_finding(EvidenceLevel::Strong, Vec::new()),
            risk_finding(EvidenceLevel::Weak, Vec::new()),
            risk_finding(EvidenceLevel::Suspicion, Vec::new()),
        ];

        assert_eq!(RiskScoreEngine::count_strong(&findings), 1);
        assert_eq!(RiskScoreEngine::count_weak(&findings), 1);
        assert_eq!(RiskScoreEngine::count_suspicious(&findings), 1);
    }
}
