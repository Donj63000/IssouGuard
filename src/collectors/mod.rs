pub mod defender;
pub mod files;
pub mod powershell_history;
pub mod processes;
pub mod registry;
pub mod run_mru;
pub mod scheduled_tasks;
pub mod services;

use crate::core::model::{Finding, FindingCategory, WindowsPaths};

/// Partie 2 : collecteur de fondation uniquement.
/// Il ne lit pas encore Defender, les processus, le registre ou les tâches.
/// Il documente seulement que le socle est prêt.
pub fn collect_foundation_findings(paths: &WindowsPaths, is_admin: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.push(Finding::informational(
        "FOUNDATION-001",
        FindingCategory::Architecture,
        "Architecture projet initialisée",
        "Les modules principaux sont présents : core, collectors, remediation, windows, tui.",
        "collectors::collect_foundation_findings",
    ));

    findings.push(Finding::informational(
        "FOUNDATION-002",
        FindingCategory::SafetyPolicy,
        "Politique de sécurité chargée",
        "La Partie 2 est non destructive et ne contacte aucun domaine suspect.",
        "collectors::collect_foundation_findings",
    ));

    findings.push(Finding::informational(
        "FOUNDATION-003",
        FindingCategory::IocDefinition,
        "IOC incident chargés",
        "Les URLs, domaines, commandes, extensions, emplacements et événements Defender connus sont définis.",
        "collectors::collect_foundation_findings",
    ));

    findings.push(Finding::informational(
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
    ));

    findings.push(Finding::informational(
        "FOUNDATION-005",
        FindingCategory::AdminStatus,
        "Statut administrateur évalué",
        if is_admin {
            "Exécution administrateur détectée. Les parties futures pourront accéder à davantage d'éléments système."
        } else {
            "Exécution non administrateur. Les parties futures resteront utiles mais certaines preuves système peuvent manquer."
        },
        "windows::admin::is_elevated",
    ));

    findings.push(Finding::informational(
        "FOUNDATION-006",
        FindingCategory::Logging,
        "Journal local activé",
        "Un fichier issaguard.log est créé dans le dossier de rapport local.",
        "core::report::write_log_line",
    ));

    findings
}
