use crate::core::model::WindowsPaths;
use std::path::PathBuf;

/// Résolution locale des chemins utiles.
/// Aucune connexion réseau.
/// Aucun accès destructif.
pub fn resolve_system_paths() -> WindowsPaths {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let executable_path = std::env::current_exe().ok();

    let user_profile = env_path("USERPROFILE").or_else(|| env_path("HOME"));
    let desktop_dir = user_profile
        .as_ref()
        .map(|p| p.join("Desktop"))
        .unwrap_or_else(|| current_dir.clone());

    let downloads_dir = user_profile.as_ref().map(|p| p.join("Downloads"));
    let temp_dir = std::env::temp_dir();

    let local_appdata = env_path("LOCALAPPDATA");
    let roaming_appdata = env_path("APPDATA");
    let program_data = env_path("ProgramData");

    let user_startup_dir = roaming_appdata.as_ref().map(|appdata| {
        appdata
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup")
    });

    let machine_startup_dir = program_data.as_ref().map(|program_data| {
        program_data
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("StartUp")
    });

    WindowsPaths {
        current_dir,
        executable_path,
        user_profile,
        desktop_dir,
        downloads_dir,
        temp_dir,
        local_appdata,
        roaming_appdata,
        program_data,
        user_startup_dir,
        machine_startup_dir,
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}
