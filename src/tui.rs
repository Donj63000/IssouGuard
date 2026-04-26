use crate::core::model::{AppResult, ExecutionMode, ReportData};
use crate::core::risk_score::RiskScoreEngine;
use std::io::{self, Write};
use std::path::Path;

pub fn print_banner(version: &str) {
    println!("IssaGuard — Faux Claude Code / mshta Incident Response");
    println!("========================================================");
    println!("Version : {version}");
    println!();
    println!("But Partie 1 : cadrage, règles de sécurité, IOC, modes, scoring et architecture.");
    println!("Aucune suppression, aucun téléchargement, aucune connexion aux domaines suspects.");
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
            Err(_) => println!("Choix invalide. Saisir 1, 2, 3, 4 ou 5."),
        }
    }
}

pub fn print_result_summary(report: &ReportData) {
    let strong = RiskScoreEngine::count_strong(&report.findings);
    let weak = RiskScoreEngine::count_weak(&report.findings);
    let suspicious = RiskScoreEngine::count_suspicious(&report.findings);

    println!();
    println!("Rapport créé");
    println!("============");
    println!("Dossier : {}", report.metadata.report_dir.display());
    println!("Mode    : {}", report.metadata.mode);
    println!("Risque  : {}", report.risk_level.label());
    println!("Message : {}", report.risk_message);
    println!();
    println!("Preuves incident affectant le score :");
    println!("  - fortes     : {strong}");
    println!("  - faibles    : {weak}");
    println!("  - suspicions : {suspicious}");
    println!();
    println!("Note : cette Partie 1 ne réalise pas encore l'audit système complet.");
    println!(
        "Ouvre report.txt, architecture.txt, iocs.txt et safety_policy.txt dans le dossier généré."
    );
}

pub fn print_opened_report(path: &Path) {
    println!();
    println!("Dernier rapport IssaGuard : {}", path.display());
    println!("Sous Windows, l'explorateur a été demandé si disponible.");
}
