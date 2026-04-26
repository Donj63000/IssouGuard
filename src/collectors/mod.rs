pub mod defender;
pub mod files;
pub mod powershell_history;
pub mod processes;
pub mod registry;
pub mod run_mru;
pub mod scheduled_tasks;
pub mod services;

use crate::core::model::{Finding, FindingCategory, WindowsPaths};

/// Partie 3 : collecteur de fondation uniquement.
/// Il documente le socle sans auditer Defender, processus, registre ou fichiers.
pub fn collect_foundation_findings(paths: &WindowsPaths, is_admin: bool) -> Vec<Finding> {
    vec![
        Finding::informational(
            "FOUNDATION-001",
            FindingCategory::Architecture,
            "Architecture projet initialisée",
            "Les modules principaux sont présents : core, collectors, remediation, windows, tui.",
            "collectors::collect_foundation_findings",
        )
        .with_tag("part3")
        .with_tag("architecture"),
        Finding::informational(
            "FOUNDATION-002",
            FindingCategory::SafetyPolicy,
            "Politique de sécurité chargée",
            "La Partie 3 est non destructive et ne contacte aucun domaine suspect.",
            "collectors::collect_foundation_findings",
        )
        .with_tag("safety"),
        Finding::informational(
            "FOUNDATION-003",
            FindingCategory::IocDefinition,
            "IOC incident chargés",
            "Les URLs, domaines, commandes, extensions, emplacements et événements Defender connus sont définis.",
            "collectors::collect_foundation_findings",
        )
        .with_tag("ioc"),
        Finding::informational(
            "FOUNDATION-004",
            FindingCategory::PathResolution,
            "Chemins Windows résolus",
            format!(
                "Bureau={}, Temp={}, Downloads={}",
                paths.desktop_dir.display(),
                paths.temp_dir.display(),
                paths
                    .downloads_dir
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "inconnu".into())
            ),
            "windows::paths::resolve_system_paths",
        )
        .with_tag("paths"),
        Finding::informational(
            "FOUNDATION-005",
            FindingCategory::AdminStatus,
            "Statut administrateur évalué",
            if is_admin {
                "Exécution administrateur détectée. Les parties futures pourront accéder à davantage d'éléments système."
            } else {
                "Exécution non administrateur. Les parties futures resteront utiles mais certaines preuves système peuvent manquer."
            },
            "windows::admin::is_elevated",
        )
        .with_tag("admin"),
        Finding::informational(
            "FOUNDATION-006",
            FindingCategory::Logging,
            "Journal local activé",
            "Un fichier issaguard.log est créé dans le dossier de rapport local.",
            "core::report::write_log_line",
        )
        .with_tag("logging"),
    ]
}

pub fn collect_data_model_findings() -> Vec<Finding> {
    vec![
        Finding::informational(
            "MODEL-001",
            FindingCategory::DataModel,
            "Type Finding défini",
            "Un finding contient l'identifiant, le niveau de preuve, la source, les IOC liés, les tags, la confiance et l'action recommandée.",
            "core::model::Finding",
        )
        .with_tag("model:finding"),
        Finding::informational(
            "MODEL-002",
            FindingCategory::DataModel,
            "Type EvidenceLevel défini",
            "Les niveaux Informational, Suspicion, Weak et Strong séparent information, soupçon, preuve faible et preuve forte.",
            "core::model::EvidenceLevel",
        )
        .with_tag("model:evidence"),
        Finding::informational(
            "MODEL-003",
            FindingCategory::DataModel,
            "Type RiskLevel défini",
            "Les niveaux NotAssessed, Green, Orange et Red préparent le scoring prudent.",
            "core::model::RiskLevel",
        )
        .with_tag("model:risk"),
        Finding::informational(
            "MODEL-004",
            FindingCategory::DataModel,
            "Type ActionRecord défini",
            "Chaque action future sera journalisée avec statut, raison, cible, réversibilité, confirmation et rollback.",
            "core::model::ActionRecord",
        )
        .with_tag("model:action"),
        Finding::informational(
            "MODEL-005",
            FindingCategory::DataModel,
            "Type TimelineEvent défini",
            "La timeline garde les étapes de l'application, des collecteurs, des findings, des actions et des rapports.",
            "core::model::TimelineEvent",
        )
        .with_tag("model:timeline"),
        Finding::informational(
            "MODEL-006",
            FindingCategory::ReportGeneration,
            "Type Report défini",
            "Le rapport central sérialise métadonnées, score, compteurs, politique, IOC, chemins, signature, findings, actions et timeline.",
            "core::model::Report",
        )
        .with_tag("model:report")
        .with_recommended_action("Continuer avec la Partie 4 pour alimenter ce modèle avec les preuves Defender."),
    ]
}
