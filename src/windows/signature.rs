use crate::core::model::ToolSignatureInfo;

/// Informations locales sur l'outil.
/// Ce n'est pas une signature cryptographique.
/// But : documenter ce qui a généré le rapport.
pub fn current_tool_signature(version: &str) -> ToolSignatureInfo {
    ToolSignatureInfo {
        tool_name: "IssaGuard".into(),
        version: version.into(),
        build_profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
        target_os: std::env::consts::OS.into(),
        target_arch: std::env::consts::ARCH.into(),
        executable_path: std::env::current_exe().ok(),
    }
}
