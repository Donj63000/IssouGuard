use std::process::Command;

pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.trim().eq_ignore_ascii_case("true");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("true");
    }

    false
}

pub fn admin_message(is_admin: bool) -> &'static str {
    if is_admin {
        "Exécution administrateur détectée. Les futures parties pourront lire davantage de preuves système."
    } else {
        "Exécution non administrateur. L'audit restera utile, mais certaines preuves Defender/registre/services peuvent manquer."
    }
}
