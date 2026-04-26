pub mod defender;
pub mod offline_scan;
pub mod persistence;
pub mod process_kill;
pub mod quarantine;

use crate::core::model::{ActionRecord, ExecutionMode};

/// Partie 2 : aucune action système réelle.
/// On documente seulement ce que le mode autorisera plus tard.
pub fn part2_planned_actions(mode: ExecutionMode) -> Vec<ActionRecord> {
    match mode {
        ExecutionMode::AuditOnly => vec![ActionRecord::skipped(
            mode,
            "Remédiation système",
            "Mode audit seul : aucune modification autorisée.",
        )],
        ExecutionMode::AuditAndPlan => vec![ActionRecord::planned(
            mode,
            "Générer un plan de nettoyage",
            "Les corrections seront proposées après collecte réelle dans les prochaines parties.",
        )],
        ExecutionMode::GuidedCleanup => vec![ActionRecord::planned(
            mode,
            "Nettoyage guidé réversible",
            "Chaque action future devra être confirmée, journalisée et réversible.",
        )],
        ExecutionMode::DefenderOfflinePlan => vec![ActionRecord::planned(
            mode,
            "Proposer Microsoft Defender Offline",
            "Le scan hors ligne ne doit pas être déclenché silencieusement.",
        )],
        ExecutionMode::OpenLastReport => Vec::new(),
    }
}
