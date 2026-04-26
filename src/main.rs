mod app;
mod collectors;
mod core;
mod remediation;
mod tui;
mod windows;

use crate::app::App;

/// Point d'entrée principal.
/// Règle de sécurité : si une erreur survient, on s'arrête proprement.
/// Aucune action destructive ne doit être faite silencieusement.
fn main() {
    if let Err(error) = App::default().run() {
        eprintln!();
        eprintln!("[ERREUR] IssaGuard s'est arrêté proprement.");
        eprintln!("Détail : {error}");
        eprintln!();
        eprintln!("Aucune suppression définitive n'a été effectuée.");
        eprintln!("Aucun domaine suspect n'a été contacté.");
        std::process::exit(1);
    }
}
