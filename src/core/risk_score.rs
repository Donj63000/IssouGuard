use crate::core::model::{EvidenceLevel, Finding, RiskAssessmentScope, RiskLevel};

pub struct RiskScoreEngine;

impl RiskScoreEngine {
    /// Partie 4 : le score peut devenir Vert/Orange/Rouge, mais seulement sur le périmètre Defender.
    /// Les processus, fichiers et persistances seront ajoutés dans les parties suivantes.
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

    pub fn message_for_scope(level: RiskLevel, scope: RiskAssessmentScope) -> &'static str {
        match (level, scope) {
            (RiskLevel::NotAssessed, _) => {
                "Score non calculé : pas encore de preuves système suffisantes."
            }
            (RiskLevel::Green, RiskAssessmentScope::DefenderEvidenceOnly) => {
                "Aucune preuve Defender liée à l'incident dans le périmètre collecté. Cela ne prouve pas encore que la machine est saine : processus, fichiers et persistances restent à auditer."
            }
            (RiskLevel::Orange, RiskAssessmentScope::DefenderEvidenceOnly) => {
                "Defender contient une trace compatible avec une tentative ou un blocage. Continuer l'audit et prévoir scans Defender / Offline selon le résultat final."
            }
            (RiskLevel::Red, RiskAssessmentScope::DefenderEvidenceOnly) => {
                "Defender contient une preuve forte ou une configuration préoccupante : autorisation/échec d'action, menace type Trojan/Stealer, protection désactivée ou exclusion suspecte. Nettoyage local + révocation sessions/mots de passe/tokens conseillés après stabilisation."
            }
            _ => level.message(),
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
    use super::*;
    use crate::core::model::{EvidenceLevel, FindingCategory};

    fn defender_finding(id: &str, level: EvidenceLevel) -> Finding {
        Finding::risk_finding(
            id,
            FindingCategory::Defender,
            "Finding Defender test",
            "Preuve Defender simulée.",
            level,
            "test",
            90,
        )
    }

    #[test]
    fn foundation_scope_is_not_assessed_even_with_risk_findings() {
        let findings =
            vec![defender_finding("TEST-001", EvidenceLevel::Strong).with_tag("risk:red")];

        let level = RiskScoreEngine::evaluate(RiskAssessmentScope::FoundationOnly, &findings);

        assert_eq!(RiskLevel::NotAssessed, level);
    }

    #[test]
    fn defender_scope_without_risk_findings_is_green() {
        let level = RiskScoreEngine::evaluate(RiskAssessmentScope::DefenderEvidenceOnly, &[]);

        assert_eq!(RiskLevel::Green, level);
    }

    #[test]
    fn defender_red_tag_forces_red_score() {
        let findings = vec![defender_finding("TEST-002", EvidenceLevel::Weak).with_tag("risk:red")];

        let level = RiskScoreEngine::evaluate(RiskAssessmentScope::DefenderEvidenceOnly, &findings);

        assert_eq!(RiskLevel::Red, level);
    }

    #[test]
    fn defender_strong_evidence_without_red_tag_is_orange() {
        let findings = vec![defender_finding("TEST-003", EvidenceLevel::Strong)];

        let level = RiskScoreEngine::evaluate(RiskAssessmentScope::DefenderEvidenceOnly, &findings);

        assert_eq!(RiskLevel::Orange, level);
    }
}
