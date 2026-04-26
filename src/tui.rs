use crate::core::model::{AppResult, ExecutionMode, Report};
use std::io::{self, Write};
use std::path::Path;

pub fn print_banner(version: &str) {
    println!("IssaGuard — Faux Claude Code / mshta Incident Response");
    println!("========================================================");
    println!("Version : {version}");
    println!();
    println!("Partie 3 : modèles de données internes et rapports robustes.");
    println!("Aucune suppression. Aucun téléchargement. Aucun contact avec les domaines suspects.");
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

    println!("Fichiers utiles dans le rapport :");
    println!("  - report.txt / report.json");
    println!("  - findings.txt / findings.json");
    println!("  - actions.txt / actions.json");
    println!("  - timeline.txt");
    println!("  - evidence_summary.txt");
    println!("  - data_model.txt");
    println!("  - issaguard.log");
    println!();

    println!("Note : cette Partie 3 ne fait pas encore l'audit réel. C'est normal que le risque soit NON ÉVALUÉ.");
}

pub fn print_opened_report(path: &Path) {
    println!();
    println!("Dernier rapport IssaGuard : {}", path.display());
    println!("Sous Windows, l'ouverture dans l'explorateur a été demandée si disponible.");
}
