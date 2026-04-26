use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

pub type AppResult<T> = Result<T, IssaError>;

#[derive(Debug, thiserror::Error)]
pub enum IssaError {
    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),

    #[error("erreur JSON : {0}")]
    Json(#[from] serde_json::Error),

    #[error("mode d'exécution invalide : {0}")]
    InvalidMode(String),

    #[error("commande PowerShell échouée : {0}")]
    #[allow(dead_code)]
    PowerShell(String),

    #[error("aucun rapport IssaGuard trouvé")]
    NoReportFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    AuditOnly,
    AuditAndPlan,
    GuidedCleanup,
    DefenderOfflinePlan,
    OpenLastReport,
}

impl ExecutionMode {
    pub fn from_menu_choice(choice: &str) -> AppResult<Self> {
        match choice.trim() {
            "1" => Ok(Self::AuditOnly),
            "2" => Ok(Self::AuditAndPlan),
            "3" => Ok(Self::GuidedCleanup),
            "4" => Ok(Self::DefenderOfflinePlan),
            "5" => Ok(Self::OpenLastReport),
            other => Err(IssaError::InvalidMode(other.to_string())),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AuditOnly => "Audit sans modification",
            Self::AuditAndPlan => "Audit + plan de nettoyage",
            Self::GuidedCleanup => "Nettoyage guidé",
            Self::DefenderOfflinePlan => "Planifier / proposer Defender Offline",
            Self::OpenLastReport => "Ouvrir le dernier rapport",
        }
    }

    pub fn is_remediation_mode(self) -> bool {
        matches!(self, Self::GuidedCleanup | Self::DefenderOfflinePlan)
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    NotAssessed,
    Green,
    Orange,
    Red,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAssessed => "NON ÉVALUÉ",
            Self::Green => "VERT",
            Self::Orange => "ORANGE",
            Self::Red => "ROUGE",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotAssessed => {
                "Score non calculé : cette étape pose l'architecture mais ne collecte pas encore les preuves système."
            }
            Self::Green => {
                "Aucune preuve locale d'exécution ou de persistance suspecte dans le périmètre audité. Scan Defender recommandé."
            }
            Self::Orange => {
                "Exécution probable ou tentative bloquée. Nettoyage Defender et scan hors ligne recommandés."
            }
            Self::Red => {
                "Compromission probable ou traces fortes. Nettoyage local + révocation sessions/mots de passe/tokens conseillés."
            }
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskAssessmentScope {
    ArchitectureOnly,
    AuditEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceLevel {
    Informational,
    Suspicion,
    Weak,
    Strong,
}

impl EvidenceLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "information",
            Self::Suspicion => "suspicion",
            Self::Weak => "preuve faible",
            Self::Strong => "preuve forte",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    Architecture,
    SafetyPolicy,
    IocDefinition,
    Defender,
    Process,
    File,
    Registry,
    ScheduledTask,
    Service,
    PowerShellHistory,
    RunMru,
    RemediationPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub evidence_level: EvidenceLevel,
    pub source: String,
    pub related_iocs: Vec<String>,
    pub tags: Vec<String>,
    pub affects_risk: bool,
    pub confidence: u8,
    pub recommended_action: Option<String>,
}

impl Finding {
    pub fn informational(
        id: impl Into<String>,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            timestamp: Local::now(),
            category,
            title: title.into(),
            description: description.into(),
            evidence_level: EvidenceLevel::Informational,
            source: source.into(),
            related_iocs: Vec::new(),
            tags: vec!["info".to_string()],
            affects_risk: false,
            confidence: 100,
            recommended_action: None,
        }
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn risk_finding(
        id: impl Into<String>,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence_level: EvidenceLevel,
        source: impl Into<String>,
        related_iocs: Vec<String>,
        tags: Vec<String>,
        confidence: u8,
        recommended_action: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            timestamp: Local::now(),
            category,
            title: title.into(),
            description: description.into(),
            evidence_level,
            source: source.into(),
            related_iocs,
            tags,
            affects_risk: true,
            confidence: confidence.min(100),
            recommended_action,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Local>,
    pub title: String,
    pub details: String,
}

impl TimelineEvent {
    pub fn now(title: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            title: title.into(),
            details: details.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub timestamp: DateTime<Local>,
    pub mode: ExecutionMode,
    pub action: String,
    pub reason: String,
    pub status: ActionStatus,
    pub reversible: bool,
    pub rollback_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Planned,
    Skipped,
    Completed,
    Failed,
}

impl ActionRecord {
    pub fn planned(
        mode: ExecutionMode,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Local::now(),
            mode,
            action: action.into(),
            reason: reason.into(),
            status: ActionStatus::Planned,
            reversible: true,
            rollback_hint: None,
        }
    }

    pub fn skipped(
        mode: ExecutionMode,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Local::now(),
            mode,
            action: action.into(),
            reason: reason.into(),
            status: ActionStatus::Skipped,
            reversible: true,
            rollback_hint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPolicy {
    pub local_only: bool,
    pub no_contact_with_suspicious_domains: bool,
    pub no_password_or_cookie_collection: bool,
    pub no_blind_deletion: bool,
    pub quarantine_instead_of_delete: bool,
    pub prefer_disable_over_delete_for_persistence: bool,
    pub defender_updates_allowed: bool,
    pub rules: Vec<String>,
    pub limitations: Vec<String>,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            local_only: true,
            no_contact_with_suspicious_domains: true,
            no_password_or_cookie_collection: true,
            no_blind_deletion: true,
            quarantine_instead_of_delete: true,
            prefer_disable_over_delete_for_persistence: true,
            defender_updates_allowed: true,
            rules: vec![
                "Ne jamais rouvrir ni télécharger claud-hub.com ou le faux site".into(),
                "Ne jamais exécuter de code Internet pendant l'analyse".into(),
                "Ne pas supprimer aveuglément setup/install/update : classer, justifier, quarantaine".into(),
                "Ne pas lire, déchiffrer ni exporter les mots de passe/cookies navigateurs".into(),
                "Ne rien envoyer vers Internet ; local-only sauf Microsoft Defender/Microsoft Update".into(),
                "Retirer uniquement les autorisations Defender liées à l'incident".into(),
                "Exporter avant modification registre/tâche/service".into(),
                "Préférer désactivation à suppression pour les persistances".into(),
                "Conserver rollback et manifest pour toute action réversible".into(),
                "Ne jamais promettre que les comptes sont sûrs après une possible exfiltration".into(),
            ],
            limitations: vec![
                "Un nettoyage local ne peut pas annuler une exfiltration déjà réalisée".into(),
                "Un score Vert signifie seulement absence de preuve dans le périmètre audité".into(),
                "Une preuve faible ne doit pas déclencher seule une suppression destructive".into(),
                "IssaGuard orchestre et documente ; il ne remplace pas Microsoft Defender".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSet {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub process_patterns: Vec<String>,
    pub command_patterns: Vec<String>,
    pub suspicious_file_names: Vec<String>,
    pub suspicious_extensions: Vec<String>,
    pub suspicious_locations: Vec<String>,
    pub persistence_locations: Vec<String>,
    pub defender_event_ids: Vec<u32>,
}

impl Default for IocSet {
    fn default() -> Self {
        Self {
            urls: vec![
                "https://claud-hub.com/app".into(),
                "https://claude-desktop-lm.gitlab.io/var/".into(),
                "https://claude-desktop-lm.gitlab.io/var/analytics.js".into(),
            ],
            domains: vec![
                "claud-hub.com".into(),
                "claude-desktop-lm.gitlab.io".into(),
                "download.active-version.com".into(),
                "active-version.com".into(),
                "desktop-version.com".into(),
                "official-version.com".into(),
                "claude-code.official-version.com".into(),
                "download-version".into(),
            ],
            process_patterns: vec![
                "mshta.exe + URL distante".into(),
                "powershell.exe + iex/irm/iwr/Invoke-WebRequest/Invoke-RestMethod".into(),
                "wscript.exe ou cscript.exe".into(),
                "chrome/msedge/brave/firefox --headless".into(),
                "AddInProcess32.exe suspect".into(),
                "cmd -> powershell -> mshta".into(),
                "Code.exe -> powershell -> mshta".into(),
            ],
            command_patterns: vec![
                "mshta https://claud-hub.com/app".into(),
                "powershell iex".into(),
                "powershell irm".into(),
                "powershell iwr".into(),
                "Invoke-WebRequest".into(),
                "Invoke-RestMethod".into(),
                "--headless".into(),
            ],
            suspicious_file_names: vec![
                "claude-code.exe".into(),
                "app".into(),
                "setup.exe".into(),
                "install.exe".into(),
                "update.exe".into(),
            ],
            suspicious_extensions: vec![
                ".hta".into(),
                ".js".into(),
                ".jse".into(),
                ".vbs".into(),
                ".vbe".into(),
                ".ps1".into(),
                ".cmd".into(),
                ".bat".into(),
                ".scr".into(),
                ".pif".into(),
                ".msi".into(),
                ".msix".into(),
                ".msixbundle".into(),
            ],
            suspicious_locations: vec![
                "%TEMP%".into(),
                "%LOCALAPPDATA%\\Temp".into(),
                "%USERPROFILE%\\Downloads".into(),
                "%USERPROFILE%\\Desktop".into(),
                "%APPDATA%".into(),
                "%LOCALAPPDATA%".into(),
                "%ProgramData%".into(),
                "Startup utilisateur".into(),
                "Startup machine".into(),
            ],
            persistence_locations: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".into(),
                "Tâches planifiées".into(),
                "Services Windows".into(),
                "Dossiers Startup".into(),
            ],
            defender_event_ids: vec![1116, 1117, 1118, 1119, 1007, 1008, 5007],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub tool_name: String,
    pub tool_version: String,
    pub generated_at: DateTime<Local>,
    pub report_dir: PathBuf,
    pub hostname: String,
    pub username: String,
    pub is_admin: bool,
    pub mode: ExecutionMode,
    pub scope: RiskAssessmentScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub metadata: ReportMetadata,
    pub risk_level: RiskLevel,
    pub risk_message: String,
    pub safety_policy: SafetyPolicy,
    pub iocs: IocSet,
    pub findings: Vec<Finding>,
    pub actions: Vec<ActionRecord>,
    pub timeline: Vec<TimelineEvent>,
}

impl ReportData {
    pub fn new(
        tool_version: impl Into<String>,
        report_dir: PathBuf,
        is_admin: bool,
        mode: ExecutionMode,
        scope: RiskAssessmentScope,
    ) -> Self {
        let risk_level = RiskLevel::NotAssessed;

        Self {
            metadata: ReportMetadata {
                tool_name: "IssaGuard".into(),
                tool_version: tool_version.into(),
                generated_at: Local::now(),
                report_dir,
                hostname: std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "inconnu".into()),
                username: std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_else(|_| "inconnu".into()),
                is_admin,
                mode,
                scope,
            },
            risk_level,
            risk_message: risk_level.message().to_string(),
            safety_policy: SafetyPolicy::default(),
            iocs: IocSet::default(),
            findings: Vec::new(),
            actions: Vec::new(),
            timeline: vec![TimelineEvent::now(
                "Initialisation",
                "Création du contexte IssaGuard Partie 1",
            )],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionMode, RiskLevel};

    #[test]
    fn menu_choices_map_to_execution_modes() {
        assert_eq!(
            ExecutionMode::from_menu_choice("1").unwrap(),
            ExecutionMode::AuditOnly
        );
        assert_eq!(
            ExecutionMode::from_menu_choice("2").unwrap(),
            ExecutionMode::AuditAndPlan
        );
        assert_eq!(
            ExecutionMode::from_menu_choice("3").unwrap(),
            ExecutionMode::GuidedCleanup
        );
        assert_eq!(
            ExecutionMode::from_menu_choice("4").unwrap(),
            ExecutionMode::DefenderOfflinePlan
        );
        assert_eq!(
            ExecutionMode::from_menu_choice("5").unwrap(),
            ExecutionMode::OpenLastReport
        );
    }

    #[test]
    fn invalid_menu_choice_is_rejected() {
        assert!(ExecutionMode::from_menu_choice("6").is_err());
        assert!(ExecutionMode::from_menu_choice("abc").is_err());
    }

    #[test]
    fn part1_risk_label_stays_not_assessed() {
        assert_eq!(RiskLevel::NotAssessed.label(), "NON ÉVALUÉ");
        assert!(RiskLevel::NotAssessed
            .message()
            .contains("ne collecte pas encore les preuves système"));
    }
}
