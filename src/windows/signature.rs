use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSignatureInfo {
    pub tool_name: String,
    pub version: String,
    pub build_profile: String,
    pub target_os: String,
}

pub fn current_tool_signature(version: &str) -> ToolSignatureInfo {
    ToolSignatureInfo {
        tool_name: "IssaGuard".into(),
        version: version.into(),
        build_profile: option_env!("PROFILE").unwrap_or("unknown").into(),
        target_os: std::env::consts::OS.into(),
    }
}
