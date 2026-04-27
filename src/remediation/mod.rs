pub mod defender;
pub mod offline_scan;
pub mod persistence;
pub mod process_kill;
pub mod quarantine;

use crate::core::model::{ActionKind, ActionRecord, ActionStatus, ExecutionMode};

/// Partie 4 : aucune action système réelle.
/// On documente seulement ce que le mode autorisera plus tard.
pub fn part4_planned_actions(mode: ExecutionMode) -> Vec<ActionRecord> {
    match mode {
        ExecutionMode::AuditOnly => vec![ActionRecord::skipped(
            mode,
            "Remédiation Defender",
            "Mode audit seul : aucune modification Defender autorisée.",
        )],
        ExecutionMode::AuditAndPlan => vec![ActionRecord::planned(
            mode,
            "Préparer un plan de nettoyage Defender",
            "Les corrections Defender seront proposées après confirmation des preuves et seulement en Partie 9.",
        )
        .with_rollback_hint("Aucun rollback : aucune modification système en Partie 4.")],
        ExecutionMode::GuidedCleanup => vec![ActionRecord::new(
            mode,
            ActionKind::Defender,
            "Collecter Defender avant nettoyage guidé",
            "Partie 4 : collecte préalable uniquement ; aucune action Defender n'est exécutée.",
            ActionStatus::Planned,
        )
        .with_target("Microsoft Defender")
        .with_rollback_hint("La Partie 4 ne modifie rien ; rollback non nécessaire.")],
        ExecutionMode::DefenderOfflinePlan => vec![ActionRecord::new(
            mode,
            ActionKind::OfflineScan,
            "Documenter le besoin éventuel de Microsoft Defender Offline",
            "Le scan hors ligne ne doit pas être déclenché silencieusement. Il sera proposé après analyse du rapport.",
            ActionStatus::Planned,
        )
        .with_target("Microsoft Defender Offline")],
        ExecutionMode::OpenLastReport => Vec::new(),
    }
}
