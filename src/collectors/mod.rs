pub mod defender;
pub mod files;
pub mod powershell_history;
pub mod processes;
pub mod registry;
pub mod run_mru;
pub mod scheduled_tasks;
pub mod services;

use crate::core::model::{Finding, FindingCategory};

pub fn collect_architecture_findings() -> Vec<Finding> {
    vec![
        Finding::informational(
            "ARCH-001",
            FindingCategory::Architecture,
            "Architecture projet initialisée",
            "Les modules principaux sont présents et prêts à recevoir les collecteurs Windows.",
            "collectors::collect_architecture_findings",
        ),
        Finding::informational(
            "SAFE-001",
            FindingCategory::SafetyPolicy,
            "Mode non destructif par défaut",
            "La Partie 1 ne stoppe aucun processus, ne modifie pas Defender, ne désactive aucune persistance et ne met rien en quarantaine.",
            "collectors::collect_architecture_findings",
        ),
        Finding::informational(
            "IOC-001",
            FindingCategory::IocDefinition,
            "IOC incident chargés",
            "Les domaines, commandes, extensions, emplacements et événements Defender connus sont intégrés au modèle.",
            "collectors::collect_architecture_findings",
        ),
    ]
}
