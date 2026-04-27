use crate::core::model::{AppResult, DefenderSnapshot, IssaError, Report, WindowsPaths};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const REQUIRED_REPORT_FILES: &[&str] = &[
    "report.txt",
    "report.json",
    "timeline.txt",
    "findings.txt",
    "findings.json",
    "actions.txt",
    "actions.json",
    "evidence_summary.txt",
    "data_model.txt",
    "rollback.json",
    "manifest.json",
    "defender_before.txt",
    "defender_after.txt",
    "defender_events.txt",
    "defender_snapshot.json",
    "suspicious_processes.txt",
    "suspicious_files.txt",
    "suspicious_registry.txt",
    "suspicious_tasks.txt",
    "suspicious_services.txt",
    "powershell_history_hits.txt",
    "runmru_hits.txt",
    "architecture.txt",
    "iocs.txt",
    "paths.txt",
    "safety_policy.txt",
    "issaguard.log",
];

pub fn create_report_dir(paths: &WindowsPaths) -> AppResult<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = paths
        .desktop_dir
        .join(format!("IssaGuard-Report-{timestamp}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn write_log_line(report_dir: &Path, message: impl AsRef<str>) -> AppResult<()> {
    fs::create_dir_all(report_dir)?;

    let log_path = report_dir.join("issaguard.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    writeln!(
        file,
        "{} | {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        message.as_ref()
    )?;

    Ok(())
}

pub fn write_report_package(report: &Report) -> AppResult<()> {
    report.validate()?;

    fs::create_dir_all(&report.metadata.report_dir)?;
    ensure_placeholder_files(&report.metadata.report_dir)?;

    write_log_line(
        &report.metadata.report_dir,
        "Écriture du package de rapport Partie 4",
    )?;

    write_json(report.metadata.report_dir.join("report.json"), report)?;
    write_json(
        report.metadata.report_dir.join("findings.json"),
        &report.findings,
    )?;
    write_json(
        report.metadata.report_dir.join("actions.json"),
        &report.actions,
    )?;

    if let Some(defender) = &report.defender {
        write_json(
            report.metadata.report_dir.join("defender_snapshot.json"),
            defender,
        )?;
    } else {
        write_json(
            report.metadata.report_dir.join("defender_snapshot.json"),
            &serde_json::json!({"note": "Aucune collecte Defender disponible."}),
        )?;
    }

    let manifest = crate::core::quarantine::QuarantineManifest::empty();
    write_json(report.metadata.report_dir.join("manifest.json"), &manifest)?;

    let rollback = serde_json::json!({
        "schema_version": &report.metadata.schema_version,
        "tool_version": &report.metadata.tool_version,
        "note": "Partie 4 : collecte Defender lecture seule. Aucune modification système, donc aucun rollback nécessaire.",
        "entries": []
    });

    write_json(report.metadata.report_dir.join("rollback.json"), &rollback)?;

    write_text(
        report.metadata.report_dir.join("report.txt"),
        render_report_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("timeline.txt"),
        render_timeline_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("findings.txt"),
        render_findings_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("actions.txt"),
        render_actions_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("evidence_summary.txt"),
        render_evidence_summary_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("data_model.txt"),
        render_data_model_txt(),
    )?;

    write_text(
        report.metadata.report_dir.join("defender_before.txt"),
        render_defender_before_txt(report.defender.as_ref()),
    )?;

    write_text(
        report.metadata.report_dir.join("defender_after.txt"),
        render_defender_after_txt(),
    )?;

    write_text(
        report.metadata.report_dir.join("defender_events.txt"),
        render_defender_events_txt(report.defender.as_ref()),
    )?;

    write_text(
        report.metadata.report_dir.join("architecture.txt"),
        render_architecture_txt(),
    )?;

    write_text(
        report.metadata.report_dir.join("iocs.txt"),
        render_iocs_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("paths.txt"),
        render_paths_txt(report),
    )?;

    write_text(
        report.metadata.report_dir.join("safety_policy.txt"),
        render_safety_policy_txt(report),
    )?;

    write_log_line(&report.metadata.report_dir, "Rapport Partie 4 terminé")?;
    Ok(())
}

fn ensure_placeholder_files(report_dir: &Path) -> AppResult<()> {
    for file in REQUIRED_REPORT_FILES {
        let path = report_dir.join(file);

        if !path.exists() {
            fs::write(
                path,
                "IssaGuard Partie 4 : fichier réservé. Le contenu réel sera ajouté par les collecteurs disponibles.\n",
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

fn write_text(path: PathBuf, contents: String) -> AppResult<()> {
    fs::write(path, contents)?;
    Ok(())
}

fn render_report_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("IssaGuard — Faux Claude Code / mshta Incident Response\n");
    out.push_str("========================================================\n\n");

    out.push_str("Résumé\n");
    out.push_str("------\n");
    out.push_str(&format!(
        "Schéma rapport       : {}\n",
        report.metadata.schema_version
    ));
    out.push_str(&format!(
        "Version outil        : {}\n",
        report.metadata.tool_version
    ));
    out.push_str(&format!(
        "Date génération      : {}\n",
        report.metadata.generated_at
    ));
    out.push_str(&format!(
        "Machine              : {}\n",
        report.metadata.hostname
    ));
    out.push_str(&format!(
        "Utilisateur          : {}\n",
        report.metadata.username
    ));
    out.push_str(&format!(
        "Admin                : {}\n",
        if report.metadata.is_admin {
            "oui"
        } else {
            "non"
        }
    ));
    out.push_str(&format!(
        "Mode                 : {}\n",
        report.metadata.mode
    ));
    out.push_str(&format!(
        "Périmètre score      : {:?}\n",
        report.metadata.scope
    ));
    out.push_str(&format!(
        "Dossier rapport      : {}\n\n",
        report.metadata.report_dir.display()
    ));

    out.push_str("Verdict\n");
    out.push_str("-------\n");
    out.push_str(&format!(
        "Risque               : {}\n",
        report.risk_level.label()
    ));
    out.push_str(&format!("Message              : {}\n", report.risk_message));
    out.push_str(&format!(
        "Findings total       : {}\n",
        report.counts.findings_total
    ));
    out.push_str(&format!(
        "Findings risque      : {}\n",
        report.counts.risk_findings_total
    ));
    out.push_str(&format!(
        "Preuves fortes       : {}\n",
        report.counts.strong_total
    ));
    out.push_str(&format!(
        "Preuves faibles      : {}\n",
        report.counts.weak_total
    ));
    out.push_str(&format!(
        "Suspicion            : {}\n\n",
        report.counts.suspicion_total
    ));

    out.push_str("Important\n");
    out.push_str("---------\n");
    out.push_str("Cette Partie 4 collecte Microsoft Defender en lecture seule.\n");
    out.push_str("Elle ne modifie aucune préférence Defender, ne lance aucun scan, ne retire aucune exclusion et ne supprime rien.\n");
    out.push_str("Un risque Vert à ce stade signifie seulement : aucune preuve Defender liée dans le périmètre collecté.\n");
    out.push_str("Les processus, fichiers, historique PowerShell, RunMRU et persistances seront audités dans les parties suivantes.\n\n");

    out.push_str("Résumé Defender\n");
    out.push_str("---------------\n");
    match &report.defender {
        Some(defender) => {
            out.push_str(&format!(
                "Collecte disponible  : {}\n",
                if defender.available {
                    "oui"
                } else {
                    "non / partielle"
                }
            ));
            out.push_str(&format!(
                "Commandes capturées  : {}\n",
                defender.command_captures.len()
            ));
            out.push_str(&format!(
                "Menaces              : {}\n",
                defender.threats.len()
            ));
            out.push_str(&format!(
                "Détections           : {}\n",
                defender.detections.len()
            ));
            out.push_str(&format!(
                "Événements ciblés    : {}\n",
                defender.events.len()
            ));
            out.push_str(&format!(
                "Erreurs collecte     : {}\n\n",
                defender.errors.len()
            ));
        }
        None => out.push_str("Aucune collecte Defender disponible.\n\n"),
    }

    out.push_str("Signature outil\n");
    out.push_str("---------------\n");
    out.push_str(&format!(
        "Nom                  : {}\n",
        report.signature.tool_name
    ));
    out.push_str(&format!(
        "Version              : {}\n",
        report.signature.version
    ));
    out.push_str(&format!(
        "Profil build         : {}\n",
        report.signature.build_profile
    ));
    out.push_str(&format!(
        "OS cible             : {}\n",
        report.signature.target_os
    ));
    out.push_str(&format!(
        "Architecture         : {}\n",
        report.signature.target_arch
    ));
    out.push_str(&format!(
        "Exécutable           : {}\n\n",
        optional_path(&report.signature.executable_path)
    ));

    out.push_str("Actions recommandées à ce stade\n");
    out.push_str("--------------------------------\n");
    out.push_str("- Lire defender_before.txt et defender_events.txt.\n");
    out.push_str("- Continuer avec la Partie 5 pour processus, PowerShell history et RunMRU.\n");
    out.push_str("- Ne pas relancer la commande mshta ni visiter les domaines IOC.\n");
    out.push_str("- Si le score est Rouge, prévoir nettoyage local guidé puis révocation sessions/mots de passe/tokens exposés.\n\n");

    out.push_str("Limites\n");
    out.push_str("-------\n");
    for limitation in &report.safety_policy.limitations {
        out.push_str(&format!("- {}\n", limitation));
    }

    out
}

fn render_findings_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("Findings IssaGuard\n");
    out.push_str("==================\n\n");

    if report.findings.is_empty() {
        out.push_str("Aucun finding enregistré.\n");
        return out;
    }

    for finding in &report.findings {
        out.push_str(&format!("{}\n", finding.short_line()));
        out.push_str(&format!("  Catégorie : {:?}\n", finding.category));
        out.push_str(&format!("  Source    : {}\n", finding.source));
        out.push_str(&format!("  Détail    : {}\n", finding.description));

        if let Some(artifact) = &finding.artifact {
            out.push_str(&format!(
                "  Artefact  : {:?} | {}\n",
                artifact.artifact_type, artifact.display_name
            ));
        }

        if !finding.related_iocs.is_empty() {
            out.push_str(&format!(
                "  IOC       : {}\n",
                finding.related_iocs.join(", ")
            ));
        }

        if !finding.tags.is_empty() {
            out.push_str(&format!("  Tags      : {}\n", finding.tags.join(", ")));
        }

        if let Some(action) = &finding.recommended_action {
            out.push_str(&format!("  Action    : {}\n", action));
        }

        if !finding.notes.is_empty() {
            out.push_str(&format!("  Notes     : {}\n", finding.notes.join(" | ")));
        }

        out.push('\n');
    }

    out
}

fn render_actions_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("Actions IssaGuard\n");
    out.push_str("=================\n\n");

    if report.actions.is_empty() {
        out.push_str("Aucune action système effectuée.\n");
        return out;
    }

    for action in &report.actions {
        out.push_str(&format!("[{}] {}\n", action.id, action.action));
        out.push_str(&format!("  Mode          : {}\n", action.mode));
        out.push_str(&format!("  Type          : {:?}\n", action.kind));
        out.push_str(&format!("  Statut        : {:?}\n", action.status));
        out.push_str(&format!(
            "  Réversible    : {}\n",
            if action.reversible { "oui" } else { "non" }
        ));
        out.push_str(&format!(
            "  Confirmation  : {}\n",
            if action.requires_confirmation {
                "oui"
            } else {
                "non"
            }
        ));

        if let Some(target) = &action.target {
            out.push_str(&format!("  Cible         : {}\n", target));
        }

        out.push_str(&format!("  Raison        : {}\n", action.reason));

        if let Some(rollback) = &action.rollback_hint {
            out.push_str(&format!("  Rollback      : {}\n", rollback));
        }

        out.push('\n');
    }

    out
}

fn render_evidence_summary_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("Résumé des niveaux de preuve\n");
    out.push_str("=============================\n\n");
    out.push_str(&format!(
        "Information     : {}\n",
        report.counts.informational_total
    ));
    out.push_str(&format!(
        "Suspicion       : {}\n",
        report.counts.suspicion_total
    ));
    out.push_str(&format!("Preuve faible   : {}\n", report.counts.weak_total));
    out.push_str(&format!(
        "Preuve forte    : {}\n",
        report.counts.strong_total
    ));
    out.push_str(&format!(
        "Affecte risque  : {}\n\n",
        report.counts.risk_findings_total
    ));
    out.push_str("Rappel : Partie 4 = preuves Defender uniquement. Un Vert ne couvre pas encore fichiers/processus/persistances.\n");

    out
}

fn render_timeline_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("Timeline IssaGuard\n");
    out.push_str("==================\n\n");

    for event in &report.timeline {
        out.push_str(&format!(
            "{} | {} | {:?} | {} | {}\n",
            event.timestamp, event.id, event.kind, event.title, event.details
        ));
    }

    out
}

fn render_defender_before_txt(defender: Option<&DefenderSnapshot>) -> String {
    let mut out = String::new();
    out.push_str("Microsoft Defender — état avant remédiation\n");
    out.push_str("===========================================\n\n");
    out.push_str(
        "Partie 4 : collecte en lecture seule. Aucune modification Defender n'a été effectuée.\n\n",
    );

    let Some(defender) = defender else {
        out.push_str("Aucune collecte Defender disponible.\n");
        return out;
    };

    out.push_str(&format!(
        "Date collecte        : {}\n",
        defender.generated_at
    ));
    out.push_str(&format!(
        "Disponible           : {}\n",
        if defender.available {
            "oui"
        } else {
            "non / partiel"
        }
    ));
    out.push_str(&format!(
        "Menaces              : {}\n",
        defender.threats.len()
    ));
    out.push_str(&format!(
        "Détections           : {}\n",
        defender.detections.len()
    ));
    out.push_str(&format!(
        "Événements           : {}\n",
        defender.events.len()
    ));
    out.push_str(&format!(
        "Erreurs              : {}\n\n",
        defender.errors.len()
    ));

    if !defender.errors.is_empty() {
        out.push_str("Erreurs de collecte\n");
        out.push_str("-------------------\n");
        for err in &defender.errors {
            out.push_str(&format!("- {}\n", err));
        }
        out.push('\n');
    }

    out.push_str("Commandes capturées\n");
    out.push_str("-------------------\n");
    for capture in &defender.command_captures {
        out.push_str(&format!("## {}\n", capture.label));
        out.push_str(&format!("Succès      : {}\n", capture.success));
        out.push_str(&format!("Code sortie : {:?}\n", capture.status_code));
        if !capture.stderr.trim().is_empty() {
            out.push_str(&format!("STDERR      : {}\n", capture.stderr.trim()));
        }
        out.push_str("STDOUT JSON :\n");
        out.push_str(if capture.stdout.trim().is_empty() {
            "<vide>\n"
        } else {
            capture.stdout.trim()
        });
        out.push_str("\n\n");
    }

    out
}

fn render_defender_after_txt() -> String {
    "Microsoft Defender — état après remédiation\n==========================================\n\nPartie 4 : aucune remédiation exécutée. Ce fichier reste informatif.\nL'état après nettoyage sera produit dans la Partie 9 quand les actions guidées seront implémentées.\n".to_string()
}

fn render_defender_events_txt(defender: Option<&DefenderSnapshot>) -> String {
    let mut out = String::new();
    out.push_str("Événements Microsoft Defender ciblés\n");
    out.push_str("====================================\n\n");
    out.push_str(
        "IDs collectés : 1116, 1117, 1118, 1119, 1007, 1008, 5007. Fenêtre : 30 jours.\n\n",
    );

    let Some(defender) = defender else {
        out.push_str("Aucune collecte Defender disponible.\n");
        return out;
    };

    if defender.events.is_empty() {
        out.push_str("Aucun événement ciblé collecté.\n");
        return out;
    }

    for event in &defender.events {
        out.push_str(&format!(
            "{} | ID={} | niveau={} | record={}\n",
            event.time_created.as_deref().unwrap_or("inconnu"),
            event
                .event_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "inconnu".into()),
            event.level_display_name.as_deref().unwrap_or("inconnu"),
            event
                .record_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "inconnu".into())
        ));
        out.push_str(&format!(
            "Machine={} | Provider={}\n",
            event.machine_name.as_deref().unwrap_or("inconnu"),
            event.provider_name.as_deref().unwrap_or("inconnu")
        ));
        out.push_str(event.message.as_deref().unwrap_or(""));
        out.push_str("\n\n---\n\n");
    }

    out
}

fn render_iocs_txt(report: &Report) -> String {
    let iocs = &report.iocs;
    let mut out = String::new();

    out.push_str("IOC cadrés pour IssaGuard\n");
    out.push_str("=========================\n\n");

    out.push_str("URLs\n----\n");
    for item in &iocs.urls {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nDomaines\n--------\n");
    for item in &iocs.domains {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nProcessus\n---------\n");
    for item in &iocs.process_patterns {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nCommandes\n---------\n");
    for item in &iocs.command_patterns {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nFichiers suspects\n-----------------\n");
    for item in &iocs.suspicious_file_names {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nExtensions suspectes\n--------------------\n");
    for item in &iocs.suspicious_extensions {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nEmplacements à inspecter\n------------------------\n");
    for item in &iocs.suspicious_locations {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nPersistances à inspecter\n------------------------\n");
    for item in &iocs.persistence_locations {
        out.push_str(&format!("- {}\n", item));
    }

    out.push_str("\nÉvénements Defender utiles\n-------------------------\n");
    for id in &iocs.defender_event_ids {
        out.push_str(&format!("- {}\n", id));
    }

    out
}

fn render_paths_txt(report: &Report) -> String {
    let p = &report.system_paths;
    let mut out = String::new();

    out.push_str("Chemins locaux résolus\n");
    out.push_str("======================\n\n");
    out.push_str(&format!(
        "current_dir          : {}\n",
        p.current_dir.display()
    ));
    out.push_str(&format!(
        "executable_path      : {}\n",
        optional_path(&p.executable_path)
    ));
    out.push_str(&format!(
        "user_profile         : {}\n",
        optional_path(&p.user_profile)
    ));
    out.push_str(&format!(
        "desktop_dir          : {}\n",
        p.desktop_dir.display()
    ));
    out.push_str(&format!(
        "downloads_dir        : {}\n",
        optional_path(&p.downloads_dir)
    ));
    out.push_str(&format!(
        "temp_dir             : {}\n",
        p.temp_dir.display()
    ));
    out.push_str(&format!(
        "local_appdata        : {}\n",
        optional_path(&p.local_appdata)
    ));
    out.push_str(&format!(
        "roaming_appdata      : {}\n",
        optional_path(&p.roaming_appdata)
    ));
    out.push_str(&format!(
        "program_data         : {}\n",
        optional_path(&p.program_data)
    ));
    out.push_str(&format!(
        "user_startup_dir     : {}\n",
        optional_path(&p.user_startup_dir)
    ));
    out.push_str(&format!(
        "machine_startup_dir  : {}\n",
        optional_path(&p.machine_startup_dir)
    ));

    out
}

fn optional_path(path: &Option<PathBuf>) -> String {
    path.as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "inconnu".into())
}

fn render_safety_policy_txt(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("Règles de sécurité IssaGuard\n");
    out.push_str("============================\n\n");

    for rule in &report.safety_policy.rules {
        out.push_str(&format!("- {}\n", rule));
    }

    out.push_str("\nLimites\n-------\n");

    for limitation in &report.safety_policy.limitations {
        out.push_str(&format!("- {}\n", limitation));
    }

    out
}

fn render_data_model_txt() -> String {
    r#"Modèles de données Partie 4
============================

La Partie 4 conserve les modèles de la Partie 3 et ajoute DefenderSnapshot.

DefenderSnapshot
----------------
Contient l'état Defender collecté en lecture seule : statut, préférences,
menaces, détections, événements, sorties brutes PowerShell et erreurs.

DefenderCommandCapture
----------------------
Journalise chaque commande PowerShell locale : label, statut, stdout, stderr,
JSON parsé. Les commandes sont en lecture seule.

DefenderEventRecord
-------------------
Représente les événements Defender opérationnels ciblés : 1116, 1117, 1118,
1119, 1007, 1008 et 5007.

Scoring Partie 4
----------------
- Vert   : aucune preuve Defender liée dans le périmètre collecté.
- Orange : trace Defender compatible tentative/blocage ou visibilité partielle.
- Rouge  : menace type Trojan/Stealer, action autorisée/échouée, protection
           désactivée, exclusion suspecte ou changement Defender préoccupant.
"#
    .to_string()
}

fn render_architecture_txt() -> String {
    r#"Arborescence cible IssaGuard
===========================

src/
  main.rs
  app.rs
  tui.rs
  core/
    mod.rs
    model.rs
    risk_score.rs
    report.rs
    timeline.rs
    quarantine.rs
  collectors/
    mod.rs
    defender.rs
    processes.rs
    files.rs
    registry.rs
    scheduled_tasks.rs
    services.rs
    powershell_history.rs
    run_mru.rs
  remediation/
    mod.rs
    defender.rs
    process_kill.rs
    persistence.rs
    quarantine.rs
    offline_scan.rs
  windows/
    mod.rs
    admin.rs
    paths.rs
    powershell.rs
    signature.rs

Partie 4
========
Objectif : collecte Defender en lecture seule.
Collecteurs actifs : collectors/defender.rs.
Remédiation : non exécutée.
"#
    .to_string()
}

pub fn latest_report_dir(paths: &WindowsPaths) -> AppResult<PathBuf> {
    let root = &paths.desktop_dir;
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
    let paths = crate::windows::paths::resolve_system_paths();
    let path = latest_report_dir(&paths)?;

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer").arg(&path).spawn();
    }

    Ok(path)
}
