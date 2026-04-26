pub mod defender;
pub mod offline_scan;
pub mod persistence;
pub mod process_kill;
pub mod quarantine;

use crate::core::model::{ActionKind, ActionRecord, ActionStatus, ExecutionMode};

/// Partie 3 : aucune action système réelle.
/// On documente seulement ce que le mode autorisera plus tard.
pub fn part3_planned_actions(mode: ExecutionMode) -> Vec<ActionRecord> {
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
        )
        .with_rollback_hint("Aucun rollback : aucun changement système en Partie 3.")],
        ExecutionMode::GuidedCleanup => vec![ActionRecord::new(
            mode,
            ActionKind::ReportOnly,
            "Préparer le nettoyage guidé réversible",
            "Chaque action future devra être confirmée, journalisée et réversible.",
            ActionStatus::Planned,
        )
        .with_rollback_hint("La Partie 3 ne modifie rien ; rollback non nécessaire.")],
        ExecutionMode::DefenderOfflinePlan => vec![ActionRecord::new(
            mode,
            ActionKind::OfflineScan,
            "Proposer Microsoft Defender Offline",
            "Le scan hors ligne ne doit pas être déclenché silencieusement.",
            ActionStatus::Planned,
        )
        .with_target("Microsoft Defender Offline")],
        ExecutionMode::OpenLastReport => Vec::new(),
    }
}
