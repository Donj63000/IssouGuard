use crate::core::model::{AppResult, IssaError};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PowerShellOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[allow(dead_code)]
pub fn run_powershell_capture(command: &str) -> AppResult<PowerShellOutput> {
    #[cfg(not(target_os = "windows"))]
    let _ = command;

    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("powershell.exe");
        c.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "echo PowerShell indisponible hors Windows >&2; exit 1",
        ]);
        c
    };

    let output = cmd.output()?;
    let result = PowerShellOutput {
        status_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    };

    if output.status.success() {
        Ok(result)
    } else {
        Err(IssaError::PowerShell(format!(
            "code={:?}, stderr={}",
            result.status_code,
            result.stderr.trim()
        )))
    }
}
