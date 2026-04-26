mod app;
mod collectors;
mod core;
mod remediation;
mod tui;
mod windows;

use crate::app::App;

fn main() {
    if let Err(error) = App::default().run() {
        eprintln!("\n[ERREUR] IssaGuard s'est arrêté proprement.");
        eprintln!("Détail : {error}");
        eprintln!("\nAucune action destructive n'a été effectuée par cette version Partie 1.");
        std::process::exit(1);
    }
}
