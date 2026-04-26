use crate::core::model::{AppResult, IssaError, ReportData};
use crate::core::risk_score::RiskScoreEngine;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REQUIRED_REPORT_FILES: &[&str] = &[
    "report.txt",
    "report.json",
    "timeline.txt",
    "findings.json",
    "actions.json",
    "rollback.json",
    "manifest.json",
    "defender_before.txt",
    "defender_after.txt",
    "suspicious_processes.txt",
    "suspicious_files.txt",
    "suspicious_registry.txt",
    "suspicious_tasks.txt",
    "suspicious_services.txt",
    "powershell_history_hits.txt",
    "runmru_hits.txt",
    "architecture.txt",
    "iocs.txt",
    "safety_policy.txt",
];

pub fn default_reports_root() -> PathBuf {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        return PathBuf::from(userprofile).join("Desktop");
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join("Desktop");
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn create_report_dir() -> AppResult<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = default_reports_root().join(format!("IssaGuard-Report-{timestamp}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn write_report_package(report: &ReportData) -> AppResult<()> {
    fs::create_dir_all(&report.metadata.report_dir)?;
    ensure_placeholder_files(&report.metadata.report_dir)?;

    write_json(report.metadata.report_dir.join("report.json"), report)?;
    write_json(
        report.metadata.report_dir.join("findings.json"),
        &report.findings,
    )?;
    write_json(
        report.metadata.report_dir.join("actions.json"),
        &report.actions,
    )?;
    write_json(
        report.metadata.report_dir.join("manifest.json"),
        &crate::core::quarantine::QuarantineManifest::empty(),
    )?;
    write_json(
        report.metadata.report_dir.join("rollback.json"),
        &serde_json::json!({
            "version": &report.metadata.tool_version,
            "note": "Partie 1 : aucune modification système, donc aucun rollback nécessaire.",
            "entries": []
        }),
    )?;

    fs::write(
        report.metadata.report_dir.join("report.txt"),
        render_report_txt(report),
    )?;
    fs::write(
        report.metadata.report_dir.join("timeline.txt"),
        render_timeline_txt(report),
    )?;
    fs::write(
        report.metadata.report_dir.join("architecture.txt"),
        render_architecture_txt(),
    )?;
    fs::write(
        report.metadata.report_dir.join("iocs.txt"),
        render_iocs_txt(report),
    )?;
    fs::write(
        report.metadata.report_dir.join("safety_policy.txt"),
        render_safety_policy_txt(report),
    )?;

    Ok(())
}

fn ensure_placeholder_files(report_dir: &Path) -> AppResult<()> {
    for file in REQUIRED_REPORT_FILES {
        let path = report_dir.join(file);
        if !path.exists() {
            fs::write(
                path,
                "IssaGuard Partie 1 : fichier réservé. Le contenu réel sera ajouté par les parties suivantes.\n",
            )?;
        }
    }
    Ok(())
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> AppResult<()> {
    let pretty = serde_json::to_string_pretty(value)?;
    fs::write(path, pretty)?;
    Ok(())
}

fn render_report_txt(report: &ReportData) -> String {
    let strong = RiskScoreEngine::count_strong(&report.findings);
    let weak = RiskScoreEngine::count_weak(&report.findings);
    let suspicious = RiskScoreEngine::count_suspicious(&report.findings);

    let mut out = String::new();
    out.push_str("IssaGuard — Faux Claude Code / mshta Incident Response\n");
    out.push_str("========================================================\n\n");
    out.push_str(&format!(
        "Version outil        : {}\n",
        report.metadata.tool_version
    ));
    out.push_str(&format!(
        "Date génération     : {}\n",
        report.metadata.generated_at
    ));
    out.push_str(&format!(
        "Machine             : {}\n",
        report.metadata.hostname
    ));
    out.push_str(&format!(
        "Utilisateur         : {}\n",
        report.metadata.username
    ));
    out.push_str(&format!(
        "Admin               : {}\n",
        if report.metadata.is_admin {
            "oui"
        } else {
            "non"
        }
    ));
    out.push_str(&format!("Mode                : {}\n", report.metadata.mode));
    out.push_str(&format!(
        "Périmètre score     : {:?}\n",
        report.metadata.scope
    ));
    out.push_str(&format!(
        "Dossier rapport     : {}\n\n",
        report.metadata.report_dir.display()
    ));

    out.push_str("Verdict\n");
    out.push_str("-------\n");
    out.push_str(&format!(
        "Risque              : {}\n",
        report.risk_level.label()
    ));
    out.push_str(&format!("Message             : {}\n", report.risk_message));
    out.push_str(&format!("Preuves fortes      : {}\n", strong));
    out.push_str(&format!("Preuves faibles     : {}\n", weak));
    out.push_str(&format!("Suspicion           : {}\n\n", suspicious));

    out.push_str("Important\n");
    out.push_str("---------\n");
    out.push_str("Cette Partie 1 met en place le cadrage, les règles de sécurité, les IOC, les modes et l'architecture.\n");
    out.push_str("Elle ne réalise pas encore l'audit système complet. Ne pas interpréter ce rapport comme une preuve que le PC est sain.\n\n");

    out.push_str("Constats\n");
    out.push_str("--------\n");
    if report.findings.is_empty() {
        out.push_str("Aucun constat enregistré.\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "- [{}] {} — {}\n  Source : {}\n  Niveau : {} | Confiance : {} | Affecte risque : {}\n",
                finding.id,
                finding.title,
                finding.description,
                finding.source,
                finding.evidence_level.label(),
                finding.confidence,
                if finding.affects_risk { "oui" } else { "non" }
            ));
            if let Some(action) = &finding.recommended_action {
                out.push_str(&format!("  Action recommandée : {}\n", action));
            }
        }
    }

    out.push_str("\nActions\n");
    out.push_str("-------\n");
    if report.actions.is_empty() {
        out.push_str("Aucune action système effectuée.\n");
    } else {
        for action in &report.actions {
            out.push_str(&format!(
                "- {:?} | {} | statut={:?} | réversible={}\n  Raison : {}\n",
                action.timestamp, action.action, action.status, action.reversible, action.reason
            ));
        }
    }

    out.push_str("\nLimites\n");
    out.push_str("-------\n");
    for limitation in &report.safety_policy.limitations {
        out.push_str(&format!("- {}\n", limitation));
    }

    out
}

fn render_timeline_txt(report: &ReportData) -> String {
    let mut out = String::new();
    out.push_str("Timeline IssaGuard\n");
    out.push_str("==================\n\n");

    for event in &report.timeline {
        out.push_str(&format!(
            "{} | {} | {}\n",
            event.timestamp, event.title, event.details
        ));
    }

    out
}

fn render_iocs_txt(report: &ReportData) -> String {
    let iocs = &report.iocs;
    let mut out = String::new();

    out.push_str("IOC cadrés pour IssaGuard\n");
    out.push_str("=========================\n\n");

    out.push_str("URLs/domaines\n");
    for item in iocs.urls.iter().chain(iocs.domains.iter()) {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nProcessus / commandes\n");
    for item in iocs
        .process_patterns
        .iter()
        .chain(iocs.command_patterns.iter())
    {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nFichiers / extensions\n");
    for item in iocs
        .suspicious_file_names
        .iter()
        .chain(iocs.suspicious_extensions.iter())
    {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nEmplacements\n");
    for item in iocs
        .suspicious_locations
        .iter()
        .chain(iocs.persistence_locations.iter())
    {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nÉvénements Defender\n");
    for id in &iocs.defender_event_ids {
        out.push_str(&format!("- {}\n", id));
    }

    out
}

fn render_safety_policy_txt(report: &ReportData) -> String {
    let mut out = String::new();

    out.push_str("Règles de sécurité IssaGuard\n");
    out.push_str("============================\n\n");

    for rule in &report.safety_policy.rules {
        out.push_str(&format!("- {}\n", rule));
    }

    out.push_str("\nLimites\n");
    for limitation in &report.safety_policy.limitations {
        out.push_str(&format!("- {}\n", limitation));
    }

    out
}

fn render_architecture_txt() -> String {
    let architecture = r#"Arborescence cible IssaGuard
===========================

src/
  main.rs
  app.rs
  tui.rs
  core/
    model.rs
    risk_score.rs
    report.rs
    timeline.rs
    quarantine.rs
  collectors/
    defender.rs
    processes.rs
    files.rs
    registry.rs
    scheduled_tasks.rs
    services.rs
    powershell_history.rs
    run_mru.rs
  remediation/
    defender.rs
    process_kill.rs
    persistence.rs
    quarantine.rs
    offline_scan.rs
  windows/
    admin.rs
    powershell.rs
    signature.rs

Modes
=====
1. Audit seul : zéro modification, preuves, rapport JSON/TXT, score.
2. Audit + plan : zéro modification, corrections proposées, risque/action.
3. Nettoyage guidé : confirmation par action, quarantaine, rollback.
4. Defender Offline : proposer/planifier, jamais silencieux.
5. Ouvrir dernier rapport.

Positionnement
==============
IssaGuard ne remplace pas Defender : il l'orchestre, collecte des preuves,
détecte des traces spécifiques, nettoie localement/réversiblement et indique le
risque restant. Aucun compte ne doit être considéré sûr si une exfiltration a
potentiellement déjà eu lieu.
"#;

    architecture.to_string()
}

pub fn latest_report_dir() -> AppResult<PathBuf> {
    let root = default_reports_root();
    let mut candidates = Vec::new();

    if root.exists() {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("IssaGuard-Report-") {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    candidates.sort();
    candidates.pop().ok_or(IssaError::NoReportFound)
}

pub fn open_latest_report_dir() -> AppResult<PathBuf> {
    let path = latest_report_dir()?;

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer").arg(&path).spawn();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = &path;
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{write_report_package, REQUIRED_REPORT_FILES};
    use crate::core::model::{ExecutionMode, ReportData, RiskAssessmentScope};
    use std::fs;
    use std::path::PathBuf;

    fn unique_temp_report_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "IssaGuard-Test-{}-{}",
            std::process::id(),
            chrono::Local::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ))
    }

    #[test]
    fn write_report_package_creates_expected_files() {
        let report_dir = unique_temp_report_dir();
        let report = ReportData::new(
            "0.1.0-test",
            report_dir.clone(),
            false,
            ExecutionMode::AuditOnly,
            RiskAssessmentScope::ArchitectureOnly,
        );

        write_report_package(&report).unwrap();

        for file in REQUIRED_REPORT_FILES {
            assert!(
                report_dir.join(file).is_file(),
                "fichier de rapport manquant: {file}"
            );
        }

        let report_txt = fs::read_to_string(report_dir.join("report.txt")).unwrap();
        assert!(report_txt.contains("NON ÉVALUÉ"));
        assert!(report_txt.contains("ne réalise pas encore l'audit système complet"));

        fs::remove_dir_all(report_dir).unwrap();
    }
}
