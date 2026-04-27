use crate::core::model::{AppResult, ExecutionMode, Report};
use std::io::{self, Write};
use std::path::Path;

pub fn print_banner(version: &str) {
    println!("IssaGuard — Faux Claude Code / mshta Incident Response");
    println!("========================================================");
    println!("Version : {version}");
    println!();
    println!("Partie 4 : collecte Microsoft Defender en lecture seule.");
    println!("Aucune suppression. Aucun nettoyage. Aucun changement Defender. Aucun contact avec les domaines suspects.");
    println!();
}

pub fn prompt_mode() -> AppResult<ExecutionMode> {
    println!("Choisir un mode :");
    println!("  1. Audit sans modification");
    println!("  2. Audit + plan nettoyage");
    println!("  3. Nettoyage guidé");
    println!("  4. Lancer/planifier Defender Offline");
    println!("  5. Ouvrir dernier rapport");
    println!();

    loop {
        print!("Choix [1-5] : ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match ExecutionMode::from_menu_choice(&input) {
            Ok(mode) => return Ok(mode),
            Err(_) => println!("Choix invalide. Saisis 1, 2, 3, 4 ou 5."),
        }
    }
}

pub fn print_result_summary(report: &Report) {
    println!();
    println!("Rapport créé");
    println!("============");
    println!("Dossier : {}", report.metadata.report_dir.display());
    println!("Mode    : {}", report.metadata.mode);
    println!(
        "Admin   : {}",
        if report.metadata.is_admin {
            "oui"
        } else {
            "non"
        }
    );
    println!("Risque  : {}", report.risk_level.label());
    println!("Message : {}", report.risk_message);
    println!();

    println!("Compteurs de findings :");
    println!("  - total      : {}", report.counts.findings_total);
    println!("  - risque     : {}", report.counts.risk_findings_total);
    println!("  - fortes     : {}", report.counts.strong_total);
    println!("  - faibles    : {}", report.counts.weak_total);
    println!("  - suspicions : {}", report.counts.suspicion_total);
    println!();

    if let Some(defender) = &report.defender {
        println!("Collecte Defender :");
        println!(
            "  - disponible : {}",
            if defender.available {
                "oui"
            } else {
                "non / partiel"
            }
        );
        println!("  - commandes  : {}", defender.command_captures.len());
        println!("  - menaces    : {}", defender.threats.len());
        println!("  - détections : {}", defender.detections.len());
        println!("  - événements : {}", defender.events.len());
        println!("  - erreurs    : {}", defender.errors.len());
        println!();
    }

    println!("Fichiers utiles dans le rapport :");
    println!("  - report.txt / report.json");
    println!("  - defender_before.txt");
    println!("  - defender_snapshot.json");
    println!("  - defender_events.txt");
    println!("  - findings.txt / findings.json");
    println!("  - evidence_summary.txt");
    println!("  - issaguard.log");
    println!();

    println!("Note : Partie 4 = score basé sur Defender seulement. Les processus, fichiers et persistances arrivent ensuite.");
}

pub fn print_opened_report(path: &Path) {
    println!();
    println!("Dernier rapport IssaGuard : {}", path.display());
    println!("Sous Windows, l'ouverture dans l'explorateur a été demandée si disponible.");
}
